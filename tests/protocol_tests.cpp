#include "protocol/ethernet_udp_parser.h"
#include "protocol/kasupp_decoder.h"
#include "protocol/yls_yaz_decoder.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

using namespace telemetry;

namespace {

std::vector<std::uint8_t> makeUdpFrame(std::size_t payloadSize) {
    std::vector<std::uint8_t> f(14 + 20 + 8 + payloadSize, 0);
    for (int i = 0; i < 6; ++i) f[i] = 0xFF;
    const std::uint8_t src[6] = {0x42,0x56,0x15,0xCB,0xBE,0xBD};
    for (int i = 0; i < 6; ++i) f[6+i] = src[i];
    f[12] = 0x08; f[13] = 0x00;
    auto* ip = f.data() + 14;
    ip[0] = 0x45;
    const auto total = static_cast<std::uint16_t>(20 + 8 + payloadSize);
    ip[2] = static_cast<std::uint8_t>(total >> 8); ip[3] = static_cast<std::uint8_t>(total);
    ip[9] = 17;
    auto* udp = ip + 20;
    udp[0] = 0; udp[1] = 101;
    udp[2] = 0; udp[3] = 206;
    const auto udpLen = static_cast<std::uint16_t>(8 + payloadSize);
    udp[4] = static_cast<std::uint8_t>(udpLen >> 8); udp[5] = static_cast<std::uint8_t>(udpLen);
    return f;
}

} // namespace

int main() {
    {
        auto frame = makeUdpFrame(400);
        const auto view = telemetry::protocol::parseEthernetIpv4Udp(frame);
        assert(view);
        assert(telemetry::protocol::isBroadcastMac(view->destinationMac));
        assert(view->payload.size() == 400);
    }

    {
        std::vector<std::uint8_t> p(400, 0);
        p[0] = 0x12; p[1] = 0x34; p[2] = 0x56; p[3] = 0x78;
        p[4] = 7;
        p[395] = 42;
        TelemetryBatch batch;
        assert(telemetry::protocol::decodeBcvmToKasupp(p, 123, "BCVM.YV1", batch));
        assert(!batch.values.empty());
        assert(batch.values.front().rawValue == 0x12345678u);
    }

    {
        std::vector<std::uint8_t> p(1432, 0);
        const auto base = telemetry::protocol::kYlsYazDataOffset;
        p[base + 0] = 0x34; p[base + 1] = 0x12;
        p[base + 18] = 0b10101101;
        p[base + 20] = 0x78; p[base + 21] = 0x56; p[base + 22] = 0x34; p[base + 23] = 0x12;
        TelemetryBatch batch;
        assert(telemetry::protocol::decodeYlsYaz(p, 456, "BKPO-A.YLS.ETH1", batch));
        assert(batch.values.size() == 12u * 3u * 22u);
        assert(batch.values[0].rawValue == 0x1234);
    }

    std::cout << "protocol_tests: OK\n";
    return 0;
}
