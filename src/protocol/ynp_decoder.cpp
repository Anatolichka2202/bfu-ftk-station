#include "protocol/ynp_decoder.h"

#include <bit>
#include <string>

namespace telemetry::protocol {
namespace {

std::uint32_t readLe32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t readLe64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(readLe32(p)) |
           (static_cast<std::uint64_t>(readLe32(p + 4)) << 32);
}

void add(TelemetryBatch& out,
         std::string_view sourceName,
         std::string device,
         std::string parameter,
         std::uint64_t value,
         std::int64_t ts) {
    out.values.push_back({
        SourceKind::Ynp,
        std::string(sourceName),
        std::move(device),
        std::move(parameter),
        value,
        ts});
}

std::uint64_t countNonZero(std::span<const std::uint8_t> data) noexcept {
    std::uint64_t count = 0;
    for (const auto byte : data) {
        if (byte != 0U) ++count;
    }
    return count;
}

} // namespace

bool decodeYnpToBcvm(std::span<const std::uint8_t> payload,
                     std::int64_t ts,
                     std::string_view sourceName,
                     TelemetryBatch& out) {
    if (payload.size() != kYnpPacketSize) return false;

    const auto counter = readLe32(payload.data());
    const auto page = counter % kYnpDiagnosticPages;

    out.captureTimestampNs = ts;
    out.values.reserve(out.values.size() + 31U);

    add(out, sourceName, "YNP", "packet_counter", counter, ts);
    add(out, sourceName, "YNP", "diagnostic_page", page, ts);
    add(out, sourceName, "YNP", "utc_ms", readLe32(payload.data() + 4), ts);

    add(out, sourceName, "NAV_RAW", "velocity_north_bits", readLe32(payload.data() + 8), ts);
    add(out, sourceName, "NAV_RAW", "velocity_east_bits", readLe32(payload.data() + 12), ts);
    add(out, sourceName, "NAV_RAW", "velocity_up_bits", readLe32(payload.data() + 16), ts);

    add(out, sourceName, "NAV_RAW", "angular_velocity_x_bits", readLe32(payload.data() + 20), ts);
    add(out, sourceName, "NAV_RAW", "angular_velocity_y_bits", readLe32(payload.data() + 24), ts);
    add(out, sourceName, "NAV_RAW", "angular_velocity_z_bits", readLe32(payload.data() + 28), ts);

    add(out, sourceName, "NAV_RAW", "acceleration_x_bits", readLe32(payload.data() + 32), ts);
    add(out, sourceName, "NAV_RAW", "acceleration_y_bits", readLe32(payload.data() + 36), ts);
    add(out, sourceName, "NAV_RAW", "acceleration_z_bits", readLe32(payload.data() + 40), ts);

    add(out, sourceName, "NAV_RAW", "angle_ksi_bits", readLe32(payload.data() + 44), ts);
    add(out, sourceName, "NAV_RAW", "angle_psi_bits", readLe32(payload.data() + 48), ts);
    add(out, sourceName, "NAV_RAW", "angle_tet_bits", readLe32(payload.data() + 52), ts);

    add(out, sourceName, "NAV_RAW", "latitude_bits", readLe64(payload.data() + 56), ts);
    add(out, sourceName, "NAV_RAW", "longitude_bits", readLe64(payload.data() + 64), ts);
    add(out, sourceName, "NAV_RAW", "altitude_bits", readLe64(payload.data() + 72), ts);

    add(out, sourceName, "YNP", "status", readLe32(payload.data() + 80), ts);
    add(out, sourceName, "YNP", "date_utc", readLe32(payload.data() + 84), ts);
    add(out, sourceName, "YNP", "gps_age_ms", readLe32(payload.data() + 88), ts);
    add(out, sourceName, "YNP", "solution_channels", readLe32(payload.data() + 92), ts);
    add(out, sourceName, "YNP", "rejected_channels", readLe32(payload.data() + 96), ts);

    const auto diagnostic = payload.subspan(kYnpMainSize, kYnpDiagnosticSize);
    add(out, sourceName, "DIAGNOSTIC", "nonzero_bytes",
        countNonZero(diagnostic), ts);

    // Even pages belong to MNP A, odd pages to MNP B.
    add(out, sourceName, "DIAGNOSTIC", "mnp_source",
        (page & 1U) == 0U ? 0U : 1U, ts);

    return true;
}

} // namespace telemetry::protocol
