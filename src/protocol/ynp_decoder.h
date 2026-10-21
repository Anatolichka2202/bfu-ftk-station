#pragma once

#include "common/telemetry_types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace telemetry::protocol {

inline constexpr std::size_t kYnpMainSize = 100U;
inline constexpr std::size_t kYnpDiagnosticSize = 412U;
inline constexpr std::size_t kYnpPacketSize =
    kYnpMainSize + kYnpDiagnosticSize;
inline constexpr std::size_t kYnpDiagnosticPages = 18U;

bool decodeYnpToBcvm(std::span<const std::uint8_t> payload,
                     std::int64_t timestampNs,
                     std::string_view sourceName,
                     TelemetryBatch& out);

} // namespace telemetry::protocol
