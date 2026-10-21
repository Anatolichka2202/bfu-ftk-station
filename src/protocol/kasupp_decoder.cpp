#include "protocol/kasupp_decoder.h"

#include <string>

namespace telemetry::protocol {
namespace {

std::uint32_t readBe32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

void add(TelemetryBatch& out, SourceKind source, std::string_view sourceName,
         std::string device, std::string parameter, std::uint64_t value,
         std::int64_t ts) {
    out.values.push_back({source, std::string(sourceName), std::move(device),
                          std::move(parameter), value, ts});
}

void addBytes(TelemetryBatch& out, SourceKind source, std::string_view sourceName,
              std::string_view device, std::string_view parameterPrefix,
              std::span<const std::uint8_t> bytes, std::int64_t ts) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        add(out, source, sourceName, std::string(device),
            std::string(parameterPrefix) + '[' + std::to_string(i) + ']', bytes[i], ts);
    }
}

} // namespace

bool decodeBcvmToKasupp(std::span<const std::uint8_t> p, std::int64_t ts,
                        std::string_view sourceName, TelemetryBatch& out) {
    if (p.size() != 400) return false;
    out.captureTimestampNs = ts;
    out.values.reserve(out.values.size() + 380);

    add(out, SourceKind::Bcvm, sourceName, "BCVM", "packet_number", readBe32(p.data()), ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "protocol_version", p[4], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "flags", p[5], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "kasupp_counter_echo", readBe32(p.data()+6), ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "ethernet_errors", p[10], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "internal_errors", p[11], ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "pyro_test_state", p[12], ts);

    addBytes(out, SourceKind::Bcvm, sourceName, "PYRO", "state", p.subspan(29, 42), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "ENGINE_DRIVES", "state", p.subspan(71, 168), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "BSEP-A", "state", p.subspan(239, 58), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "BSEP-B", "state", p.subspan(297, 58), ts);
    addBytes(out, SourceKind::Bcvm, sourceName, "PROCESSORS", "state", p.subspan(355, 40), ts);
    add(out, SourceKind::Bcvm, sourceName, "BCVM", "cyclogram_step", p[395], ts);
    return true;
}

bool decodeKasuppToBcvm(std::span<const std::uint8_t> p, std::int64_t ts,
                        std::string_view sourceName, TelemetryBatch& out) {
    if (p.size() != 100) return false;
    out.captureTimestampNs = ts;
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "packet_number", readBe32(p.data()), ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "protocol_version", p[4], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "command_0", p[5], ts);
    add(out, SourceKind::Kasupp, sourceName, "KASUPP", "command_1", p[6], ts);
    return true;
}

} // namespace telemetry::protocol
