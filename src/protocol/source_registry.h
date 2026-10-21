#pragma once

#include "common/telemetry_types.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace telemetry::protocol {

using MacAddress = std::array<std::uint8_t, 6>;

struct SourceDescriptor {
    MacAddress mac;
    SourceKind kind;
    std::string_view name;
};

std::span<const SourceDescriptor> knownSources() noexcept;
std::optional<SourceDescriptor> classifySource(const MacAddress& mac) noexcept;
std::string buildCaptureFilter();

} // namespace telemetry::protocol
