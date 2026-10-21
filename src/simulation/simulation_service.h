#pragma once

#include "telemetry/decoder_service.h"

#include <atomic>
#include <cstdint>
#include <semaphore>
#include <thread>

namespace telemetry::simulation {

struct SimulationStats {
    std::uint64_t generated{};
    std::uint64_t queueDrops{};
};

class SimulationService {
public:
    SimulationService(PacketQueue& output,
                      std::counting_semaphore<1024>& outputReady);
    ~SimulationService();

    void start();
    void stop();

    bool running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    SimulationStats stats() const noexcept {
        return {generated_.load(), queueDrops_.load()};
    }

private:
    void run();

    PacketQueue& output_;
    std::counting_semaphore<1024>& outputReady_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<std::uint64_t> generated_{0};
    std::atomic<std::uint64_t> queueDrops_{0};
};

} // namespace telemetry::simulation
