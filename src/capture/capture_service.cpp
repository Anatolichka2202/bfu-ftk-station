#include "capture/capture_service.h"

#include <chrono>
#include <cstring>
#include <mutex>

#if defined(BSU_FTK_HAS_PCAP)
#include <pcap.h>
#endif

namespace telemetry {

CaptureService::CaptureService(PacketQueue& output, std::counting_semaphore<1024>& outputReady)
    : output_(output), outputReady_(outputReady) {}

CaptureService::~CaptureService() { stop(); }

std::vector<CaptureDevice> CaptureService::availableDevices(std::string& error) {
    std::vector<CaptureDevice> out;
#if defined(BSU_FTK_HAS_PCAP)
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        error = errbuf;
        return out;
    }
    for (auto* dev = devices; dev; dev = dev->next) {
        out.push_back({dev->name ? dev->name : "", dev->description ? dev->description : ""});
    }
    pcap_freealldevs(devices);
#else
    error = "Built without Npcap/libpcap support";
#endif
    return out;
}

bool CaptureService::start(std::string deviceName, std::string bpfFilter, std::string& error) {
    if (running_.load(std::memory_order_acquire)) {
        error = "Capture already running";
        return false;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    stopRequested_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);
#if !defined(BSU_FTK_HAS_PCAP)
    (void)deviceName;
    (void)bpfFilter;
    running_.store(false);
    error = "Built without Npcap/libpcap support";
    return false;
#else
    captured_ = queueDrops_ = pcapReceived_ = pcapDropped_ = pcapIfDropped_ = 0;
    {
        std::scoped_lock lock(errorMutex_);
        lastError_.clear();
    }
    thread_ = std::thread([this, device = std::move(deviceName), filter = std::move(bpfFilter)]() mutable {
        run(std::move(device), std::move(filter));
    });
    return true;
#endif
}

void CaptureService::stop() {
    stopRequested_.store(true, std::memory_order_release);
    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false);
}

CaptureStats CaptureService::stats() const noexcept {
    return {captured_.load(), queueDrops_.load(), pcapReceived_.load(),
            pcapDropped_.load(), pcapIfDropped_.load()};
}

std::string CaptureService::lastError() const {
    std::scoped_lock lock(errorMutex_);
    return lastError_;
}

void CaptureService::run(std::string deviceName, std::string bpfFilter) {
#if defined(BSU_FTK_HAS_PCAP)
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* handle = pcap_create(deviceName.c_str(), errbuf);
    if (!handle) {
        std::scoped_lock lock(errorMutex_);
        lastError_ = errbuf;
        running_.store(false);
        return;
    }

    pcap_set_snaplen(handle, 2048);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1);
    pcap_set_buffer_size(handle, 4 * 1024 * 1024);
#ifdef PCAP_TSTAMP_HOST_HIPREC_UNSYNCED
    (void)pcap_set_tstamp_type(handle, PCAP_TSTAMP_HOST_HIPREC_UNSYNCED);
#endif
    int timestampPrecision = PCAP_TSTAMP_PRECISION_MICRO;
#ifdef PCAP_TSTAMP_PRECISION_NANO
    if (pcap_set_tstamp_precision(handle, PCAP_TSTAMP_PRECISION_NANO) == 0) {
        timestampPrecision = PCAP_TSTAMP_PRECISION_NANO;
    }
#endif
#ifdef PCAP_ERROR_ACTIVATED
    (void)pcap_set_immediate_mode(handle, 1);
#endif

    const int activateResult = pcap_activate(handle);
    if (activateResult < 0) {
        std::scoped_lock lock(errorMutex_);
        lastError_ = pcap_geterr(handle);
        pcap_close(handle);
        running_.store(false);
        return;
    }

    if (!bpfFilter.empty()) {
        bpf_program program{};
        if (pcap_compile(handle, &program, bpfFilter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(handle, &program) < 0) {
            std::scoped_lock lock(errorMutex_);
            lastError_ = pcap_geterr(handle);
            pcap_freecode(&program);
            pcap_close(handle);
            running_.store(false);
            return;
        }
        pcap_freecode(&program);
    }

    while (!stopRequested_.load(std::memory_order_acquire)) {
        pcap_pkthdr* header = nullptr;
        const u_char* bytes = nullptr;
        const int rc = pcap_next_ex(handle, &header, &bytes);
        if (rc == 0) continue;
        if (rc < 0) {
            if (rc != PCAP_ERROR_BREAK) {
                std::scoped_lock lock(errorMutex_);
                lastError_ = pcap_geterr(handle);
            }
            break;
        }

        RawPacket packet;
        const auto fractional = static_cast<std::int64_t>(header->ts.tv_usec);
        packet.captureTimestampNs = static_cast<std::int64_t>(header->ts.tv_sec) * 1'000'000'000LL +
            (timestampPrecision == PCAP_TSTAMP_PRECISION_NANO ? fractional : fractional * 1000LL);
        packet.capturedLength = header->caplen;
        packet.wireLength = header->len;
        packet.bytes.assign(bytes, bytes + header->caplen);

        ++captured_;
        if (output_.tryPush(std::move(packet))) {
            outputReady_.release();
        } else {
            ++queueDrops_;
        }
    }

    pcap_stat stat{};
    if (pcap_stats(handle, &stat) == 0) {
        pcapReceived_ = stat.ps_recv;
        pcapDropped_ = stat.ps_drop;
        pcapIfDropped_ = stat.ps_ifdrop;
    }
    pcap_close(handle);
#else
    (void)deviceName;
    (void)bpfFilter;
#endif
    running_.store(false);
}

} // namespace telemetry
