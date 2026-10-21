#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace telemetry {

enum class SourceKind : std::uint8_t {
    Unknown,
    Bcvm,
    Kasupp,
    Yls
};

struct TelemetryValue {
    SourceKind source{SourceKind::Unknown};
    std::string sourceName;
    std::string device;
    std::string parameter;
    std::uint64_t rawValue{};
    std::int64_t captureTimestampNs{};
};

struct TelemetryBatch {
    std::int64_t captureTimestampNs{};
    std::vector<TelemetryValue> values;
};

inline const char* toString(SourceKind source) noexcept {
    switch (source) {
    case SourceKind::Bcvm: return "BCVM";
    case SourceKind::Kasupp: return "KASUPP";
    case SourceKind::Yls: return "YLS";
    default: return "UNKNOWN";
    }
}

} // namespace telemetry
