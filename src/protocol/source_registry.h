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
};

inline constexpr std::uint32_t kYnpIpv4 = 0xC0A811F0U; // 192.168.17.240
inline constexpr std::uint16_t kYnpSourcePort = 200U;

std::span<const SourceDescriptor> knownSources() noexcept;
std::optional<SourceDescriptor> classifySource(const MacAddress& mac) noexcept;
std::optional<SourceDescriptor> classifySource(const MacAddress& mac,
                                               std::uint32_t sourceIpv4,
                                               std::uint16_t sourcePort) noexcept;
std::string buildCaptureFilter();

} // namespace telemetry::protocol
