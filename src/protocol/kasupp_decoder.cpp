#include "protocol/kasupp_decoder.h"

#include <string>

namespace telemetry::protocol {
namespace {

constexpr std::size_t kBcvmSize = 400;
constexpr std::size_t kKasuppSize = 100;
constexpr std::size_t kBcvmCrcOffset = 398;
constexpr std::size_t kKasuppCrcOffset = 98;
constexpr std::uint8_t kProtocolVersion = 2;

std::uint16_t readBe16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t readBe32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

std::uint16_t crc16CcittFalse(
    std::span<const std::uint8_t> data) noexcept {
    std::uint16_t remainder = 0xFFFFU;
    for (const auto byte : data) {
        remainder = static_cast<std::uint16_t>(
            remainder ^ (static_cast<std::uint16_t>(byte) << 8));
        for (int bit = 0; bit < 8; ++bit) {
            remainder = (remainder & 0x8000U) != 0
                ? static_cast<std::uint16_t>((remainder << 1) ^ 0x1021U)
                : static_cast<std::uint16_t>(remainder << 1);
        }
    }
    return remainder;
}

bool hasValidCrc(std::span<const std::uint8_t> payload,
                 std::size_t crcOffset) noexcept {
    return payload.size() >= crcOffset + 2 &&
           crc16CcittFalse(payload.first(crcOffset)) ==
               readBe16(payload.data() + crcOffset);
}

bool isNormalBcvmMode(std::uint8_t flags) noexcept {
    const auto mode = static_cast<std::uint8_t>((flags >> 5) & 0x07U);
    return mode >= 1U && mode <= 3U;
}

void add(TelemetryBatch& out, SourceKind source, std::string_view sourceName,
         std::string device, std::string parameter, std::uint64_t value,
         std::int64_t ts) {
    out.values.push_back({source, std::string(sourceName), std::move(device),
                          std::move(parameter), value, ts});
}

void addBytes(TelemetryBatch& out, SourceKind source,
              std::string_view sourceName, std::string_view device,
              std::string_view parameterPrefix,
              std::span<const std::uint8_t> bytes, std::int64_t ts) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        add(out, source, sourceName, std::string(device),
            std::string(parameterPrefix) + '[' + std::to_string(i) + ']',
            bytes[i], ts);
    }
}

} // namespace

bool decodeBcvmToKasupp(std::span<const std::uint8_t> payload,
                        std::int64_t ts,
                        std::string_view sourceName,
                        TelemetryBatch& out) {
    if (payload.size() != kBcvmSize ||
        payload[4] != kProtocolVersion ||
        !hasValidCrc(payload, kBcvmCrcOffset) ||
        !isNormalBcvmMode(payload[5])) {
        return false;
    }

    out.captureTimestampNs = ts;
    out.values.reserve(out.values.size() + 380);

    add(out, SourceKind::Bcvm, sourceName, "BCVM", "packet_number",
        readBe32(payload.data()), ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "protocol_version",
        payload[4], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "flags", payload[5], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "board_mode",
        (payload[5] >> 5) & 0x07U, ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "kasupp_counter_echo",
        readBe32(payload.data() + 6), ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "ethernet_errors",
        payload[10], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "internal_errors",
        payload[11], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "pyro_test_state",
        payload[12], ts);

    addBytes(out, SourceKind::Bcvm, sourceName, "PYRO", "state",
             payload.subspan(29, 42), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "ENGINE_DRIVES", "state",
             payload.subspan(71, 168), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "BSEP-A", "state",
             payload.subspan(239, 58), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "BSEP-B", "state",
             payload.subspan(297, 58), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "PROCESSORS", "state",
             payload.subspan(355, 40), ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "cyclogram_step",
        payload[395], ts);
    return true;
}

bool decodeKasuppToBcvm(std::span<const std::uint8_t> payload,
                        std::int64_t ts,
                        std::string_view sourceName,
                        TelemetryBatch& out) {
    if (payload.size() != kKasuppSize ||
        payload[4] != kProtocolVersion ||
        !hasValidCrc(payload, kKasuppCrcOffset)) {
        return false;
    }

    out.captureTimestampNs = ts;
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "packet_number",
        readBe32(payload.data()), ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "protocol_version",
        payload[4], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "command_0",
        payload[5], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "command_1",
        payload[6], ts);
    return true;
}

} // namespace telemetry::protocol
