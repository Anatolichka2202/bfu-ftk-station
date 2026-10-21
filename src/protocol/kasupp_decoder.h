#pragma once

#include "common/telemetry_types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace telemetry::protocol {

bool decodeBcvmToKasupp(std::span<const std::uint8_t> payload,
                        std::int64_t timestampNs,
                        std::string_view sourceName,
                        TelemetryBatch& out);

bool decodeKasuppToBcvm(std::span<const std::uint8_t> payload,
                        std::int64_t timestampNs,
                        std::string_view sourceName,
                        TelemetryBatch& out);

} // namespace telemetry::protocol
