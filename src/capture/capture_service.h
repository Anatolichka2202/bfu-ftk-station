#pragma once

#include "telemetry/decoder_service.h"

#include <atomic>
#include <cstdint>
#include <semaphore>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace telemetry {

struct CaptureDevice {
    std::string name;
    std::string description;
};

struct CaptureStats {
    std::uint64_t captured{};
    std::uint64_t queueDrops{};
    std::uint64_t pcapReceived{};
    std::uint64_t pcapDropped{};
    std::uint64_t pcapInterfaceDropped{};
};

class CaptureService {
public:
    CaptureService(PacketQueue& output, std::counting_semaphore<1024>& outputReady);
    ~CaptureService();

    static std::vector<CaptureDevice> availableDevices(std::string& error);

    bool start(std::string deviceName, std::string bpfFilter, std::string& error);
    void stop();
    bool running() const noexcept { return running_.load(); }
    CaptureStats stats() const noexcept;
    std::string lastError() const;

private:
    void run(std::string deviceName, std::string bpfFilter);

    PacketQueue& output_;
    std::counting_semaphore<1024>& outputReady_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<std::uint64_t> captured_{0};
    std::atomic<std::uint64_t> queueDrops_{0};
    std::atomic<std::uint64_t> pcapReceived_{0};
    std::atomic<std::uint64_t> pcapDropped_{0};
    std::atomic<std::uint64_t> pcapIfDropped_{0};
    mutable std::mutex errorMutex_;
    std::string lastError_;
};

} // namespace telemetry
