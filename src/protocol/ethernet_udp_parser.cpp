#include "protocol/ethernet_udp_parser.h"

#include <algorithm>

namespace telemetry::protocol {
namespace {

std::uint16_t readBe16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t readBe32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

} // namespace

bool isBroadcastMac(const MacAddress& mac) noexcept {
    return std::all_of(mac.begin(), mac.end(), [](std::uint8_t b) { return b == 0xFF; });
}

std::optional<UdpDatagramView> parseEthernetIpv4Udp(std::span<const std::uint8_t> frame) noexcept {
    if (frame.size() < 14) return std::nullopt;

    UdpDatagramView out;
    std::copy_n(frame.data(), 6, out.destinationMac.begin());
    std::copy_n(frame.data() + 6, 6, out.sourceMac.begin());

    std::size_t l3Offset = 14;
    std::uint16_t etherType = readBe16(frame.data() + 12);

    // Accept one or more 802.1Q / 802.1ad tags.
    while (etherType == 0x8100 || etherType == 0x88A8) {
        if (frame.size() < l3Offset + 4) return std::nullopt;
        etherType = readBe16(frame.data() + l3Offset + 2);
        l3Offset += 4;
    }

    if (etherType != 0x0800 || frame.size() < l3Offset + 20) return std::nullopt;

    const auto* ip = frame.data() + l3Offset;
    const auto version = static_cast<std::uint8_t>(ip[0] >> 4);
    const auto ihl = static_cast<std::size_t>((ip[0] & 0x0F) * 4);
    if (version != 4 || ihl < 20 || frame.size() < l3Offset + ihl + 8) return std::nullopt;
    if (ip[9] != 17) return std::nullopt; // UDP

    const auto totalLength = readBe16(ip + 2);
    if (totalLength < ihl + 8) return std::nullopt;

    out.sourceIpv4 = readBe32(ip + 12);
    out.destinationIpv4 = readBe32(ip + 16);

    const auto udpOffset = l3Offset + ihl;
    const auto* udp = frame.data() + udpOffset;
    out.sourcePort = readBe16(udp);
    out.destinationPort = readBe16(udp + 2);

    const auto udpLength = readBe16(udp + 4);
    if (udpLength < 8) return std::nullopt;

    const auto payloadOffset = udpOffset + 8;
    const auto declaredPayload = static_cast<std::size_t>(udpLength - 8);
    const auto ipAvailable = std::min<std::size_t>(frame.size() - payloadOffset,
        static_cast<std::size_t>(totalLength - ihl - 8));
    const auto payloadSize = std::min(declaredPayload, ipAvailable);
    out.payload = frame.subspan(payloadOffset, payloadSize);
    return out;
}

} // namespace telemetry::protocol
