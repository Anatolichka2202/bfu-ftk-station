#include "telemetry/decoder_service.h"

#include "protocol/ethernet_udp_parser.h"
#include "protocol/kasupp_decoder.h"
#include "protocol/source_registry.h"
#include "protocol/yls_yaz_decoder.h"

namespace telemetry {

DecoderService::DecoderService(PacketQueue& input,
                               std::counting_semaphore<1024>& inputReady,
                               BatchQueue& output)
    : input_(input), inputReady_(inputReady), output_(output) {}

DecoderService::~DecoderService() { stop(); }

void DecoderService::start() {
    if (thread_.joinable()) return;
    stopRequested_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
}

void DecoderService::stop() {
    if (!thread_.joinable()) return;
    stopRequested_.store(true, std::memory_order_release);
    inputReady_.release();
    thread_.join();
}

DecoderStats DecoderService::stats() const noexcept {
    return {packetsSeen_.load(), packetsDecoded_.load(), parseErrors_.load(),
            unknownSources_.load(), batchDrops_.load()};
}

void DecoderService::run() {
    while (!stopRequested_.load(std::memory_order_acquire)) {
        inputReady_.acquire();
        if (stopRequested_.load(std::memory_order_acquire)) break;

        RawPacket packet;
        if (!input_.tryPop(packet)) {
            continue;
        }

        ++packetsSeen_;
        const auto udp = protocol::parseEthernetIpv4Udp(packet.bytes);
        if (!udp || !protocol::isBroadcastMac(udp->destinationMac)) {
            ++parseErrors_;
            continue;
        }

        const auto source = protocol::classifySource(udp->sourceMac);
        if (!source) {
            ++unknownSources_;
            continue;
        }

        TelemetryBatch batch;
        bool decoded = false;
        switch (source->kind) {
        case SourceKind::Bcvm:
            decoded = protocol::decodeBcvmToKasupp(udp->payload, packet.captureTimestampNs,
                                                   source->name, batch);
            break;
        case SourceKind::Kasupp:
            decoded = protocol::decodeKasuppToBcvm(udp->payload, packet.captureTimestampNs,
                                                   source->name, batch);
            break;
        case SourceKind::Yls:
            decoded = protocol::decodeYlsYaz(udp->payload, packet.captureTimestampNs,
                                             source->name, batch);
            break;
        default:
            break;
        }

        if (!decoded) {
            ++parseErrors_;
            continue;
        }
        ++packetsDecoded_;
        if (!output_.tryPush(std::move(batch))) {
            ++batchDrops_;
        }
    }
}

} // namespace telemetry
