#pragma once

#include "protocol/source_registry.h"

#include <cstdint>
#include <optional>
#include <span>

namespace telemetry::protocol {

struct UdpDatagramView {
    MacAddress destinationMac{};
    MacAddress sourceMac{};
    std::uint32_t sourceIpv4{};
    std::uint32_t destinationIpv4{};
    std::uint16_t sourcePort{};
    std::uint16_t destinationPort{};
    std::span<const std::uint8_t> payload;
};

std::optional<UdpDatagramView> parseEthernetIpv4Udp(std::span<const std::uint8_t> frame) noexcept;
bool isBroadcastMac(const MacAddress& mac) noexcept;

} // namespace telemetry::protocol
