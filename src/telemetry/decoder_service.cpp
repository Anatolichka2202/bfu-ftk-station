#include "telemetry/decoder_service.h"

#include "protocol/ethernet_udp_parser.h"
#include "protocol/kasupp_decoder.h"
#include "protocol/source_registry.h"
#include "protocol/yls_yaz_decoder.h"
#include "protocol/ynp_decoder.h"

#include <algorithm>
#include <string>

namespace telemetry {
namespace {

protocol::MacAddress sourceMacOf(const RawPacket& packet) noexcept {
    protocol::MacAddress mac{};
    if (packet.bytes.size() >= 12) {
        std::copy_n(packet.bytes.data() + 6, 6, mac.begin());
    }
    return mac;
}

void addLinkValue(TelemetryBatch& batch,
                  const protocol::SourceDescriptor& source,
                  std::string parameter,
                  std::uint64_t value,
                  std::int64_t ts) {
    batch.values.push_back({
        source.kind,
        std::string(source.name),
        "LINK",
        std::move(parameter),
        value,
        ts});
}

void addLinkObservation(TelemetryBatch& batch,
                        const protocol::SourceDescriptor& source,
                        const RawPacket& packet,
                        const protocol::UdpDatagramView* udp) {
    batch.captureTimestampNs = packet.captureTimestampNs;

    addLinkValue(batch, source, "captured_length",
                 packet.capturedLength, packet.captureTimestampNs);
    addLinkValue(batch, source, "wire_length",
                 packet.wireLength, packet.captureTimestampNs);
    addLinkValue(batch, source, "configured_ipv4",
                 source.ipv4, packet.captureTimestampNs);
    addLinkValue(batch, source, "configured_port",
                 source.port, packet.captureTimestampNs);

    if (!udp) return;

    addLinkValue(batch, source, "source_ipv4",
                 udp->sourceIpv4, packet.captureTimestampNs);
    addLinkValue(batch, source, "destination_ipv4",
                 udp->destinationIpv4, packet.captureTimestampNs);
    addLinkValue(batch, source, "source_port",
                 udp->sourcePort, packet.captureTimestampNs);
    addLinkValue(batch, source, "destination_port",
                 udp->destinationPort, packet.captureTimestampNs);
    addLinkValue(batch, source, "udp_payload_bytes",
                 udp->payload.size(), packet.captureTimestampNs);
}

} // namespace

DecoderService::DecoderService(PacketQueue& input,
                               std::counting_semaphore<1024>& inputReady,
                               BatchQueue& output,
                               PacketJournalQueue& journal)
    : input_(input), inputReady_(inputReady), output_(output),
      journal_(journal) {}

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
    return {packetsSeen_.load(), packetsDecoded_.load(), packetsIgnored_.load(),
            decodeErrors_.load(), batchDrops_.load(), journalDrops_.load()};
}

void DecoderService::run() {
    while (!stopRequested_.load(std::memory_order_acquire)) {
        inputReady_.acquire();
        if (stopRequested_.load(std::memory_order_acquire)) break;

        RawPacket packet;
        if (!input_.tryPop(packet)) continue;

        ++packetsSeen_;

        // Journal EVERYTHING first, including unknown sources, malformed
        // frames, ARP, IPv6 and any frames addressed to other subscribers.
        // The journal is independent of payload decoding.
        if (!journal_.tryPush(packet)) {
            ++journalDrops_;
        }

        if (packet.bytes.size() < 14) {
            ++packetsIgnored_;
            continue;
        }

        const auto source = protocol::classifySource(sourceMacOf(packet));
        if (!source) {
            ++packetsIgnored_;
            continue;
        }

        const auto udp = protocol::parseEthernetIpv4Udp(packet.bytes);

        TelemetryBatch batch;
        addLinkObservation(batch, *source, packet,
                           udp ? &*udp : nullptr);

        // A known source without a payload decoder is still visible in the
        // station as RAW/LINK traffic.
        if (source->kind == SourceKind::Raw) {
            if (!output_.tryPush(std::move(batch))) {
                ++batchDrops_;
            }
            continue;
        }

        if (!udp) {
            ++packetsIgnored_;
            if (!output_.tryPush(std::move(batch))) {
                ++batchDrops_;
            }
            continue;
        }

        bool decoded = false;
        switch (source->kind) {
        case SourceKind::Bcvm:
            decoded = protocol::decodeBcvmToKasupp(
                udp->payload, packet.captureTimestampNs, source->name, batch);
            break;
        case SourceKind::Kasupp:
            decoded = protocol::decodeKasuppToBcvm(
                udp->payload, packet.captureTimestampNs, source->name, batch);
            break;
        case SourceKind::Yls:
            decoded = protocol::decodeYlsYaz(
                udp->payload, packet.captureTimestampNs, source->name, batch);
            break;
        case SourceKind::Ynp:
            decoded = protocol::decodeYnpToBcvm(
                udp->payload, packet.captureTimestampNs, source->name, batch);
            break;
        case SourceKind::Raw:
        case SourceKind::Unknown:
            break;
        }

        if (decoded) {
            ++packetsDecoded_;
        } else {
            ++decodeErrors_;
        }

        // Even when the payload format is not yet implemented or is invalid,
        // the station still reports that this known Ethernet subscriber was
        // physically heard.
        if (!output_.tryPush(std::move(batch))) {
            ++batchDrops_;
        }
    }
}

} // namespace telemetry
