#pragma once

#include "common/telemetry_types.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace telemetry::protocol {

using MacAddress = std::array<std::uint8_t, 6>;

struct SourceDescriptor {
    MacAddress mac;
    SourceKind kind;
    std::string_view name;
    std::string_view stage;
    std::string_view block;
    std::string_view cell;
    std::uint32_t ipv4{};
    std::uint16_t port{};
    bool reserved{};
};

std::span<const SourceDescriptor> knownSources() noexcept;
std::optional<SourceDescriptor> classifySource(const MacAddress& mac) noexcept;
std::string buildCaptureFilter();

} // namespace telemetry::protocol
