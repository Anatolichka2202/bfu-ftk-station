#pragma once

#include "common/raw_packet.h"

#include <cstdint>
#include <vector>

namespace telemetry::simulation {

std::vector<RawPacket> makeSimulationTick(
    std::uint32_t counter,
    std::int64_t timestampNs);

} // namespace telemetry::simulation
