#pragma once

#include "common/bounded_spsc_queue.h"
#include "common/raw_packet.h"
#include "common/telemetry_types.h"

#include <atomic>
#include <cstdint>
#include <semaphore>
#include <thread>

namespace telemetry {

using PacketQueue = BoundedSpscQueue<RawPacket, 1024>;
using BatchQueue = BoundedSpscQueue<TelemetryBatch, 256>;
using PacketJournalQueue = BoundedSpscQueue<RawPacket, 4096>;

struct DecoderStats {
    std::uint64_t packetsSeen{};
    std::uint64_t packetsDecoded{};
    std::uint64_t packetsIgnored{};
    std::uint64_t decodeErrors{};
    std::uint64_t batchDrops{};
    std::uint64_t journalDrops{};
};

class DecoderService {
public:
    DecoderService(PacketQueue& input,
                   std::counting_semaphore<1024>& inputReady,
                   BatchQueue& output,
                   PacketJournalQueue& journal);
    ~DecoderService();

    void start();
    void stop();
    DecoderStats stats() const noexcept;

private:
    void run();

    PacketQueue& input_;
    std::counting_semaphore<1024>& inputReady_;
    BatchQueue& output_;
    PacketJournalQueue& journal_;
    std::thread thread_;
    std::atomic<bool> stopRequested_{false};

    std::atomic<std::uint64_t> packetsSeen_{0};
    std::atomic<std::uint64_t> packetsDecoded_{0};
    std::atomic<std::uint64_t> packetsIgnored_{0};
    std::atomic<std::uint64_t> decodeErrors_{0};
    std::atomic<std::uint64_t> batchDrops_{0};
    std::atomic<std::uint64_t> journalDrops_{0};
};

} // namespace telemetry
