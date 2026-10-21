#pragma once

#include "common/telemetry_types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace telemetry::protocol {

// Actual packed layout from YLS-main/yls/inc/protocol.h, not stale offset comments.
inline constexpr std::size_t kYlsYazDataOffset = 223;
inline constexpr std::size_t kYazRecordSize = 24;
inline constexpr std::size_t kBkdCount = 12;
inline constexpr std::size_t kYazPerBkd = 3;
inline constexpr std::size_t kYlsYazBytes = kBkdCount * kYazPerBkd * kYazRecordSize;
inline constexpr std::size_t kMinimumYlsPayloadForYaz = kYlsYazDataOffset + kYlsYazBytes;

bool decodeYlsYaz(std::span<const std::uint8_t> payload,
                  std::int64_t timestampNs,
                  std::string_view sourceName,
                  TelemetryBatch& out);

} // namespace telemetry::protocol
