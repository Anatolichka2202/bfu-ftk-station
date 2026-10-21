#pragma once

#include "common/telemetry_types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace telemetry::protocol {

inline constexpr std::size_t kBcvmPagedSize = 1024U;
inline constexpr std::size_t kBcvmPagedCrcOffset = 1022U;
inline constexpr std::size_t kKasuppNormalSize = 64U;
inline constexpr std::size_t kKasuppNormalCrcOffset = 62U;

inline constexpr std::size_t kBcvmLegacyOrFileSize = 400U;
inline constexpr std::size_t kBcvmLegacyOrFileCrcOffset = 398U;
inline constexpr std::size_t kKasuppLegacyOrFileSize = 100U;
inline constexpr std::size_t kKasuppLegacyOrFileCrcOffset = 98U;

inline constexpr std::uint8_t kKasuppProtocolVersion = 2U;

std::uint8_t bcvmPageFromPacketCounter(std::uint32_t counter) noexcept;

bool decodeBcvmToKasupp(std::span<const std::uint8_t> payload,
                        std::int64_t timestampNs,
                        std::string_view sourceName,
                        TelemetryBatch& out);

bool decodeKasuppToBcvm(std::span<const std::uint8_t> payload,
                        std::int64_t timestampNs,
                        std::string_view sourceName,
                        TelemetryBatch& out);

} // namespace telemetry::protocol
