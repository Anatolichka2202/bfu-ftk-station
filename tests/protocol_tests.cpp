#include "protocol/ethernet_udp_parser.h"
#include "protocol/kasupp_decoder.h"
#include "protocol/source_registry.h"
#include "protocol/yls_yaz_decoder.h"
#include "protocol/ynp_decoder.h"
#include "simulation/simulated_packets.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

using namespace telemetry;

namespace {

bool decodeFrame(const RawPacket& packet, TelemetryBatch& batch) {
    const auto udp = protocol::parseEthernetIpv4Udp(packet.bytes);
    if (!udp) return false;

    const auto source = protocol::classifySource(
        udp->sourceMac, udp->sourceIpv4, udp->sourcePort);
    if (!source) return false;

    switch (source->kind) {
    case SourceKind::Bcvm:
        return protocol::decodeBcvmToKasupp(
            udp->payload, packet.captureTimestampNs, source->name, batch);
    case SourceKind::Kasupp:
        return protocol::decodeKasuppToBcvm(
            udp->payload, packet.captureTimestampNs, source->name, batch);
    case SourceKind::Yls:
        return protocol::decodeYlsYaz(
            udp->payload, packet.captureTimestampNs, source->name, batch);
    case SourceKind::Ynp:
        return protocol::decodeYnpToBcvm(
            udp->payload, packet.captureTimestampNs, source->name, batch);
    default:
        return false;
    }
}

std::uint64_t valueOf(const TelemetryBatch& batch,
                      const char* parameter) {
    for (const auto& value : batch.values) {
        if (value.parameter == parameter) return value.rawValue;
    }
    assert(false && "parameter not found");
    return 0;
}

} // namespace

int main() {
    {
        auto packets = simulation::makeSimulationTick(0, 123456789);
        assert(packets.size() == 4);

        for (const auto& packet : packets) {
            TelemetryBatch batch;
            assert(decodeFrame(packet, batch));
            assert(!batch.values.empty());
        }

        // The station is not an addressee. Destination MAC must not affect
        // decoding after the NIC has captured the frame.
        auto foreignDestination = packets[0];
        foreignDestination.bytes[0] = 0x00;
        foreignDestination.bytes[1] = 0x11;
        foreignDestination.bytes[2] = 0x22;
        foreignDestination.bytes[3] = 0x33;
        foreignDestination.bytes[4] = 0x44;
        foreignDestination.bytes[5] = 0x55;
        TelemetryBatch batch;
        assert(decodeFrame(foreignDestination, batch));
    }

    {
        for (std::uint32_t counter = 0; counter < 10; ++counter) {
            auto packets = simulation::makeSimulationTick(counter, counter);
            TelemetryBatch batch;
            assert(decodeFrame(packets[0], batch));
            assert(valueOf(batch, "page") ==
                   protocol::bcvmPageFromPacketCounter(counter));
        }
    }

    {
        auto packets = simulation::makeSimulationTick(0, 100);
        TelemetryBatch ynp;
        assert(decodeFrame(packets[3], ynp));
        assert(valueOf(ynp, "packet_counter") == 0);
        assert(valueOf(ynp, "diagnostic_page") == 0);
        assert(valueOf(ynp, "nonzero_bytes") > 0);

        packets = simulation::makeSimulationTick(1, 110);
        ynp = {};
        assert(decodeFrame(packets[3], ynp));
        assert(valueOf(ynp, "diagnostic_page") == 1);
        assert(valueOf(ynp, "mnp_source") == 1);
        assert(valueOf(ynp, "nonzero_bytes") == 0);
    }

    {
        auto packets = simulation::makeSimulationTick(0, 100);
        auto frame = packets[0].bytes;
        frame.pop_back();
        assert(!protocol::parseEthernetIpv4Udp(frame));

        frame = packets[0].bytes;
        frame[14 + 6] = 0x20; // IPv4 MF flag.
        assert(!protocol::parseEthernetIpv4Udp(frame));
    }

    {
        auto packets = simulation::makeSimulationTick(0, 100);
        auto frame = packets[0];
        auto udp = protocol::parseEthernetIpv4Udp(frame.bytes);
        assert(udp);

        std::vector<std::uint8_t> corrupted(
            udp->payload.begin(), udp->payload.end());
        corrupted[20] ^= 0x01;

        TelemetryBatch batch;
        assert(!protocol::decodeBcvmToKasupp(
            corrupted, 100, "BCVM.YV1", batch));
    }

    std::cout << "protocol_tests: OK\n";
    return 0;
}
