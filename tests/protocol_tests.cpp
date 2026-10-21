#include "protocol/ethernet_udp_parser.h"
#include "protocol/kasupp_decoder.h"
#include "protocol/yls_yaz_decoder.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

using namespace telemetry;

namespace {

std::uint16_t crc16CcittFalse(std::span<const std::uint8_t> data) {
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

void seal(std::vector<std::uint8_t>& payload, std::size_t crcOffset) {
    const auto crc = crc16CcittFalse(
        std::span<const std::uint8_t>(payload.data(), crcOffset));
    payload[crcOffset] = static_cast<std::uint8_t>(crc >> 8);
    payload[crcOffset + 1] = static_cast<std::uint8_t>(crc);
}

std::vector<std::uint8_t> makeUdpFrame(std::size_t payloadSize) {
    std::vector<std::uint8_t> f(14 + 20 + 8 + payloadSize, 0);
    for (int i = 0; i < 6; ++i) f[i] = 0xFF;

    const std::uint8_t src[6] =
        {0x42, 0x56, 0x15, 0xCB, 0xBE, 0xBD};
    for (int i = 0; i < 6; ++i) f[6 + i] = src[i];

    f[12] = 0x08;
    f[13] = 0x00;

    auto* ip = f.data() + 14;
    ip[0] = 0x45;
    const auto total =
        static_cast<std::uint16_t>(20 + 8 + payloadSize);
    ip[2] = static_cast<std::uint8_t>(total >> 8);
    ip[3] = static_cast<std::uint8_t>(total);
    ip[9] = 17;

    auto* udp = ip + 20;
    udp[0] = 0;
    udp[1] = 101;
    udp[2] = 0;
    udp[3] = 206;

    const auto udpLen =
        static_cast<std::uint16_t>(8 + payloadSize);
    udp[4] = static_cast<std::uint8_t>(udpLen >> 8);
    udp[5] = static_cast<std::uint8_t>(udpLen);

    return f;
}

} // namespace

int main() {
    {
        auto frame = makeUdpFrame(400);
        const auto view =
            telemetry::protocol::parseEthernetIpv4Udp(frame);
        assert(view);
        assert(telemetry::protocol::isBroadcastMac(
            view->destinationMac));
        assert(view->payload.size() == 400);
    }

    {
        auto fragmented = makeUdpFrame(400);
        fragmented[14 + 6] = 0x20; // IPv4 MF flag.
        assert(!telemetry::protocol::parseEthernetIpv4Udp(
            fragmented));
    }

    {
        auto truncated = makeUdpFrame(400);
        truncated.pop_back();
        assert(!telemetry::protocol::parseEthernetIpv4Udp(
            truncated));
    }

    {
        std::vector<std::uint8_t> p(400, 0);
        p[0] = 0x12;
        p[1] = 0x34;
        p[2] = 0x56;
        p[3] = 0x78;
        p[4] = 2;
        p[5] = static_cast<std::uint8_t>(3U << 5);
        p[395] = 42;
        seal(p, 398);

        TelemetryBatch batch;
        assert(telemetry::protocol::decodeBcvmToKasupp(
            p, 123, "BCVM.YV1", batch));
        assert(!batch.values.empty());
        assert(batch.values.front().rawValue == 0x12345678u);

        p[20] ^= 0x01;
        TelemetryBatch corruptedBatch;
        assert(!telemetry::protocol::decodeBcvmToKasupp(
            p, 123, "BCVM.YV1", corruptedBatch));
    }

    {
        std::vector<std::uint8_t> p(100, 0);
        p[0] = 0x00;
        p[1] = 0x00;
        p[2] = 0x00;
        p[3] = 0x11;
        p[4] = 2;
        p[5] = 0x05;
        p[6] = 0x03;
        seal(p, 98);

        TelemetryBatch batch;
        assert(telemetry::protocol::decodeKasuppToBcvm(
            p, 321, "KASUPP.ETH1", batch));
        assert(batch.values.size() == 4);
    }

    {
        std::vector<std::uint8_t> p(
            telemetry::protocol::kExpectedYlsPayloadSize, 0);

        const auto base =
            telemetry::protocol::kYlsYazDataOffset;
        p[base + 0] = 0x34;
        p[base + 1] = 0x12;
        p[base + 18] = 0b10101101;
        p[base + 20] = 0x78;
        p[base + 21] = 0x56;
        p[base + 22] = 0x34;
        p[base + 23] = 0x12;

        TelemetryBatch batch;
        assert(telemetry::protocol::decodeYlsYaz(
            p, 456, "BKPO-A.YLS.ETH1", batch));
        assert(batch.values.size() == 12u * 3u * 22u);
        assert(batch.values[0].rawValue == 0x1234);

        p.push_back(0);
        TelemetryBatch wrongSize;
        assert(!telemetry::protocol::decodeYlsYaz(
            p, 456, "BKPO-A.YLS.ETH1", wrongSize));
    }

    std::cout << "protocol_tests: OK\n";
    return 0;
}
