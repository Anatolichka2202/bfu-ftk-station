#include "protocol/kasupp_decoder.h"

#include "protocol/crc16.h"

#include <string>

namespace telemetry::protocol {
namespace {

std::uint16_t readBe16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t readBe32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

void add(TelemetryBatch& out, SourceKind source,
         std::string_view sourceName, std::string device,
         std::string parameter, std::uint64_t value,
         std::int64_t ts) {
    out.values.push_back({
        source, std::string(sourceName), std::move(device),
        std::move(parameter), value, ts});
}

void addBytes(TelemetryBatch& out, SourceKind source,
              std::string_view sourceName, std::string_view device,
              std::string_view parameterPrefix,
              std::span<const std::uint8_t> bytes,
              std::int64_t ts) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        add(out, source, sourceName, std::string(device),
            std::string(parameterPrefix) + '[' +
                std::to_string(i) + ']',
            bytes[i], ts);
    }
}

void addCommonBcvm(std::span<const std::uint8_t> p,
                   std::int64_t ts,
                   std::string_view sourceName,
                   TelemetryBatch& out,
                   std::string_view device) {
    add(out, SourceKind::Bcvm, sourceName, std::string(device),
        "packet_number", readBe32(p.data()), ts);
    add(out, SourceKind::Bcvm, sourceName, std::string(device),
        "protocol_version", p[4], ts);
    add(out, SourceKind::Bcvm, sourceName, std::string(device),
        "flags", p[5], ts);
    add(out, SourceKind::Bcvm, sourceName, std::string(device),
        "board_mode", (p[5] >> 5) & 0x07U, ts);
    add(out, SourceKind::Bcvm, sourceName, std::string(device),
        "kasupp_counter_echo", readBe32(p.data() + 6), ts);
}

bool decodePagedBcvm(std::span<const std::uint8_t> p,
                     std::int64_t ts,
                     std::string_view sourceName,
                     TelemetryBatch& out) {
    if (p.size() != kBcvmPagedSize ||
        p[4] != kKasuppProtocolVersion ||
        !verifyTrailingCrc16Be(p, kBcvmPagedCrcOffset)) {
        return false;
    }

    const auto packet = readBe32(p.data());
    const auto page = bcvmPageFromPacketCounter(packet);

    out.captureTimestampNs = ts;
    addCommonBcvm(p, ts, sourceName, out, "BCVM");
    add(out, SourceKind::Bcvm, sourceName, "BCVM",
        "page", page, ts);

    switch (page) {
    case 1:
        add(out, SourceKind::Bcvm, sourceName, "BCVM",
            "ethernet_errors", p[10], ts);
        add(out, SourceKind::Bcvm, sourceName, "BCVM",
            "internal_errors", p[11], ts);
        add(out, SourceKind::Bcvm, sourceName, "BCVM",
            "pyro_test_state", p[12], ts);
        add(out, SourceKind::Bcvm, sourceName, "BCVM",
            "cyclogram_step", p[13], ts);

        addBytes(out, SourceKind::Bcvm, sourceName,
                 "PROCESSORS", "state", p.subspan(30, 40), ts);
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "ASN_ECHO", "byte", p.subspan(70, 100), ts);
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "PYRO", "state", p.subspan(170, 42), ts);
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "BSEP-A", "state", p.subspan(212, 58), ts);
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "BSEP-B", "state", p.subspan(270, 58), ts);
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "ENGINE_DRIVES_1_7", "state",
                 p.subspan(328, 144), ts);
        break;

    case 2:
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "MNP-A_PAGE2", "byte", p.subspan(10, 240), ts);
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "MNP-B_PAGE2", "byte", p.subspan(250, 240), ts);
        break;

    case 3:
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "ENGINE_DRIVES_1_6", "state",
                 p.subspan(10, 72), ts);
        break;

    case 4:
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "ENGINE_DRIVES_7_12", "state",
                 p.subspan(10, 72), ts);
        break;

    case 5:
        addBytes(out, SourceKind::Bcvm, sourceName,
                 "ASN_ECHO", "byte", p.subspan(10, 100), ts);
        break;

    default:
        // Pages 6..10 are intentionally left at common fields only until
        // their wire maps are provided.
        break;
    }

    return true;
}

bool decodeLegacyOrFileBcvm(std::span<const std::uint8_t> p,
                            std::int64_t ts,
                            std::string_view sourceName,
                            TelemetryBatch& out) {
    if (p.size() != kBcvmLegacyOrFileSize ||
        p[4] != kKasuppProtocolVersion ||
        !verifyTrailingCrc16Be(
            p, kBcvmLegacyOrFileCrcOffset)) {
        return false;
    }

    out.captureTimestampNs = ts;
    addCommonBcvm(p, ts, sourceName, out, "BCVM_LEGACY_FILE");

    const auto mode = static_cast<std::uint8_t>((p[5] >> 5) & 0x07U);
    if (mode == 2U) {
        add(out, SourceKind::Bcvm, sourceName,
            "FILE_UPLOAD_STATUS", "fragment_number",
            readBe16(p.data() + 10), ts);
        return true;
    }

    if (mode == 3U) {
        add(out, SourceKind::Bcvm, sourceName,
            "FILE_READ_STATUS", "total_fragments",
            readBe16(p.data() + 10), ts);
        add(out, SourceKind::Bcvm, sourceName,
            "FILE_READ_STATUS", "fragment_number",
            readBe16(p.data() + 12), ts);
        add(out, SourceKind::Bcvm, sourceName,
            "FILE_READ_STATUS", "fragment_length",
            p[14], ts);
        return true;
    }

    // Compatibility with the currently deployed 400-byte normal frame.
    add(out, SourceKind::Bcvm, sourceName, "BCVM_LEGACY",
        "ethernet_errors", p[10], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM_LEGACY",
        "internal_errors", p[11], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM_LEGACY",
        "pyro_test_state", p[12], ts);
    addBytes(out, SourceKind::Bcvm, sourceName,
             "PYRO_LEGACY", "state", p.subspan(29, 42), ts);
    addBytes(out, SourceKind::Bcvm, sourceName,
             "BSEP-A_LEGACY", "state", p.subspan(239, 58), ts);
    addBytes(out, SourceKind::Bcvm, sourceName,
             "BSEP-B_LEGACY", "state", p.subspan(297, 58), ts);
    add(out, SourceKind::Bcvm, sourceName,
        "BCVM_LEGACY", "cyclogram_step", p[395], ts);
    return true;
}

} // namespace

std::uint8_t bcvmPageFromPacketCounter(std::uint32_t counter) noexcept {
    return static_cast<std::uint8_t>((counter % 10U) + 1U);
}

bool decodeBcvmToKasupp(std::span<const std::uint8_t> payload,
                        std::int64_t ts,
                        std::string_view sourceName,
                        TelemetryBatch& out) {
    if (payload.size() == kBcvmPagedSize) {
        return decodePagedBcvm(payload, ts, sourceName, out);
    }
    if (payload.size() == kBcvmLegacyOrFileSize) {
        return decodeLegacyOrFileBcvm(
            payload, ts, sourceName, out);
    }
    return false;
}

bool decodeKasuppToBcvm(std::span<const std::uint8_t> p,
                        std::int64_t ts,
                        std::string_view sourceName,
                        TelemetryBatch& out) {
    std::size_t crcOffset = 0;
    if (p.size() == kKasuppNormalSize) {
        crcOffset = kKasuppNormalCrcOffset;
    } else if (p.size() == kKasuppLegacyOrFileSize) {
        crcOffset = kKasuppLegacyOrFileCrcOffset;
    } else {
        return false;
    }

    if (p[4] != kKasuppProtocolVersion ||
        !verifyTrailingCrc16Be(p, crcOffset)) {
        return false;
    }

    out.captureTimestampNs = ts;
    add(out, SourceKind::Kasupp, sourceName, "KASUPP",
        "packet_number", readBe32(p.data()), ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP",
        "protocol_version", p[4], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP",
        "command_0", p[5], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP",
        "command_1", p[6], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP",
        "frame_size", p.size(), ts);

    if (p.size() == kKasuppLegacyOrFileSize &&
        p[5] == 0x05U && p[6] == 0x02U) {
        add(out, SourceKind::Kasupp, sourceName,
            "FILE_UPLOAD", "total_fragments",
            readBe16(p.data() + 7), ts);
        add(out, SourceKind::Kasupp, sourceName,
            "FILE_UPLOAD", "fragment_number",
            readBe16(p.data() + 9), ts);
        add(out, SourceKind::Kasupp, sourceName,
            "FILE_UPLOAD", "fragment_length",
            p[11], ts);
    } else if (p.size() == kKasuppLegacyOrFileSize &&
               p[5] == 0x05U && p[6] == 0x03U) {
        add(out, SourceKind::Kasupp, sourceName,
            "FILE_READ", "fragment_number",
            readBe16(p.data() + 7), ts);
    }

    return true;
}

} // namespace telemetry::protocol
