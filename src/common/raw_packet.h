#pragma once

#include <cstdint>
#include <vector>

namespace telemetry {

struct RawPacket {
    std::int64_t captureTimestampNs{};
    std::uint32_t capturedLength{};
    std::uint32_t wireLength{};
    std::vector<std::uint8_t> bytes;
};

} // namespace telemetry
