#include "protocol/crc16.h"

namespace telemetry::protocol {

std::uint16_t crc16CcittFalse(
    std::span<const std::uint8_t> data) noexcept {
    std::uint16_t remainder = 0xFFFFU;
    for (const auto byte : data) {
        remainder = static_cast<std::uint16_t>(
            remainder ^ (static_cast<std::uint16_t>(byte) << 8));
        for (int bit = 0; bit < 8; ++bit) {
            remainder = (remainder & 0x8000U) != 0
                ? static_cast<std::uint16_t>(
                      (remainder << 1) ^ 0x1021U)
                : static_cast<std::uint16_t>(remainder << 1);
        }
    }
    return remainder;
}

void writeTrailingCrc16Be(
    std::span<std::uint8_t> frame,
    std::size_t crcOffset) noexcept {
    if (frame.size() < crcOffset + 2U) return;
    const auto crc = crc16CcittFalse(
        std::span<const std::uint8_t>(frame.data(), crcOffset));
    frame[crcOffset] = static_cast<std::uint8_t>(crc >> 8);
    frame[crcOffset + 1U] = static_cast<std::uint8_t>(crc);
}

bool verifyTrailingCrc16Be(
    std::span<const std::uint8_t> frame,
    std::size_t crcOffset) noexcept {
    if (frame.size() < crcOffset + 2U) return false;
    const auto expected =
        static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(frame[crcOffset]) << 8) |
            frame[crcOffset + 1U]);
    return crc16CcittFalse(frame.first(crcOffset)) == expected;
}

} // namespace telemetry::protocol
