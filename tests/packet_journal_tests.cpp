#include "simulation/simulated_packets.h"
#include "telemetry/decoder_service.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <semaphore>
#include <thread>
#include <vector>

using namespace telemetry;

int main() {
    PacketQueue packets;
    BatchQueue decoded;
    PacketJournalQueue journal;
    std::counting_semaphore<1024> ready{0};
    DecoderService worker(packets, ready, decoded, journal);
    const auto generated = simulation::makeSimulationTick(12, 123456789);
    if (generated.size() != 4) return 1;

    std::vector<RawPacket> input = generated;

    // A well-formed packet from a MAC not in the configured registry.
    auto unknown = input.front();
    unknown.bytes[6] = 0x8A;
    unknown.bytes[7] = 0xED;
    unknown.bytes[8] = 0x01;
    unknown.bytes[9] = 0x02;
    unknown.bytes[10] = 0x03;
    unknown.bytes[11] = 0x04;
    input.push_back(unknown);

    // ARP (not UDP) from a known subscriber.
    RawPacket arp;
    arp.captureTimestampNs = 123456790;
    arp.bytes.assign(60, 0);
    for (int i = 0; i < 6; ++i) {
        arp.bytes[6 + i] = generated[0].bytes[6 + i];
        arp.bytes[i] = 0xff;
    }
    arp.bytes[12] = 0x08;
    arp.bytes[13] = 0x06;
    arp.capturedLength = 60;
    arp.wireLength = 60;
    input.push_back(arp);

    // Even a truncated frame belongs in the raw journal.
    RawPacket truncated;
    truncated.captureTimestampNs = 123456791;
    truncated.bytes = {1, 2, 3, 4, 5, 6, 7, 8};
    truncated.capturedLength = 8;
    truncated.wireLength = 8;
    input.push_back(truncated);

    worker.start();
    for (const auto& packet : input) {
        if (!packets.tryPush(packet)) {
            worker.stop();
            std::cerr << "Input queue unexpectedly full\n";
            return 2;
        }
        ready.release();
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (journal.approximateSize() < input.size() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    worker.stop();

    if (journal.approximateSize() != input.size()) {
        std::cerr << "Not all captured frames reached journal\n";
        return 3;
    }

    for (std::size_t i = 0; i < input.size(); ++i) {
        RawPacket packet;
        if (!journal.tryPop(packet) || packet.bytes != input[i].bytes ||
            packet.captureTimestampNs != input[i].captureTimestampNs) {
            std::cerr << "Journal changed or reordered raw frames\n";
            return 4;
        }
    }

    const auto stats = worker.stats();
    if (stats.packetsSeen != input.size() || stats.journalDrops != 0 ||
        stats.packetsIgnored < 2) {
        std::cerr << "Incorrect decoder/journal accounting\n";
        return 5;
    }

    std::cout << "packet_journal_tests: OK\n";
    return 0;
}
