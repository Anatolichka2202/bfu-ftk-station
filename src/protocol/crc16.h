#pragma once

#include <cstdint>
#include <span>

namespace telemetry::protocol {

std::uint16_t crc16CcittFalse(
    std::span<const std::uint8_t> data) noexcept;

void writeTrailingCrc16Be(
    std::span<std::uint8_t> frame,
    std::size_t crcOffset) noexcept;

bool verifyTrailingCrc16Be(
    std::span<const std::uint8_t> frame,
    std::size_t crcOffset) noexcept;

} // namespace telemetry::protocol
