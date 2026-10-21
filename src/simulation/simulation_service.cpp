#include "simulation/simulation_service.h"

#include "simulation/simulated_packets.h"

#include <chrono>

namespace telemetry::simulation {

SimulationService::SimulationService(
    PacketQueue& output,
    std::counting_semaphore<1024>& outputReady)
    : output_(output), outputReady_(outputReady) {}

SimulationService::~SimulationService() {
    stop();
}

void SimulationService::start() {
    if (running_.exchange(true, std::memory_order_acq_rel))
        return;

    if (thread_.joinable())
        thread_.join();

    generated_.store(0);
    queueDrops_.store(0);
    stopRequested_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
}

void SimulationService::stop() {
    stopRequested_.store(true, std::memory_order_release);
    if (thread_.joinable())
        thread_.join();
    running_.store(false, std::memory_order_release);
}

void SimulationService::run() {
    using clock = std::chrono::steady_clock;
    auto next = clock::now();
    std::uint32_t counter = 0;

    while (!stopRequested_.load(std::memory_order_acquire)) {
        const auto nowSystem =
            std::chrono::system_clock::now().time_since_epoch();
        const auto ts = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            nowSystem)
                            .count();

        auto packets = makeSimulationTick(counter++, ts);
        for (auto& packet : packets) {
            if (output_.tryPush(std::move(packet))) {
                ++generated_;
                outputReady_.release();
            } else {
                ++queueDrops_;
            }
        }

        next += std::chrono::milliseconds(10);
        std::this_thread::sleep_until(next);
    }

    running_.store(false, std::memory_order_release);
}

} // namespace telemetry::simulation
