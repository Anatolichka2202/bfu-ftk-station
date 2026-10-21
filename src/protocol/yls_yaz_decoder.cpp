#include "protocol/yls_yaz_decoder.h"

#include <string>

namespace telemetry::protocol {
namespace {

std::uint16_t readLe16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0]) |
          (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t readLe32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
          (static_cast<std::uint32_t>(p[1]) << 8) |
          (static_cast<std::uint32_t>(p[2]) << 16) |
          (static_cast<std::uint32_t>(p[3]) << 24);
}

void add(TelemetryBatch& out, std::string_view sourceName,
         const std::string& device, const char* parameter,
         std::uint64_t value, std::int64_t ts) {
    out.values.push_back(
        {SourceKind::Yls, std::string(sourceName), device, parameter, value, ts});
}

} // namespace

bool decodeYlsYaz(std::span<const std::uint8_t> payload,
                  std::int64_t ts,
                  std::string_view sourceName,
                  TelemetryBatch& out) {
    if (payload.size() != kExpectedYlsPayloadSize) return false;

    out.captureTimestampNs = ts;
    out.values.reserve(out.values.size() +
                       kBkdCount * kYazPerBkd * 22);

    for (std::size_t bkd = 0; bkd < kBkdCount; ++bkd) {
        for (std::size_t yaz = 0; yaz < kYazPerBkd; ++yaz) {
            const auto index = bkd * kYazPerBkd + yaz;
            const auto* p = payload.data() + kYlsYazDataOffset +
                            index * kYazRecordSize;
            const auto device = "BKD-" + std::to_string(bkd + 1) +
                                "/YAZ-" + std::to_string(yaz + 1);

            add(out, sourceName, device, "engine_revs1", readLe16(p + 0), ts);
            add(out, sourceName, device, "engine_revs2", readLe16(p + 2), ts);
            add(out, sourceName, device, "engine_revs3", readLe16(p + 4), ts);
            add(out, sourceName, device, "engine_revs4", readLe16(p + 6), ts);
            add(out, sourceName, device, "engine_revs5", readLe16(p + 8), ts);
            add(out, sourceName, device, "tp_data1_2_3", readLe16(p + 10), ts);
            add(out, sourceName, device, "tp_data1_2_3_2", readLe16(p + 12), ts);
            add(out, sourceName, device, "tp_data4", readLe16(p + 14), ts);
            add(out, sourceName, device, "tp_data5", readLe16(p + 16), ts);

            const auto flags18 = p[18];
            add(out, sourceName, device, "flags18_raw", flags18, ts);
            add(out, sourceName, device, "danger", flags18 & 0x01u, ts);
            add(out, sourceName, device, "pressure20_code",
                (flags18 >> 2) & 0x07u, ts);
            add(out, sourceName, device, "pressure30_code",
                (flags18 >> 5) & 0x07u, ts);

            const auto flags19 = p[19];
            add(out, sourceName, device, "flags19_raw", flags19, ts);
            add(out, sourceName, device, "rotation_deviation1",
                (flags19 >> 0) & 0x01u, ts);
            add(out, sourceName, device, "rotation_deviation2",
                (flags19 >> 1) & 0x01u, ts);
            add(out, sourceName, device, "rotation_deviation3",
                (flags19 >> 2) & 0x01u, ts);
            add(out, sourceName, device, "control_pressure20",
                (flags19 >> 4) & 0x01u, ts);
            add(out, sourceName, device, "control_pressure30",
                (flags19 >> 5) & 0x01u, ts);
            add(out, sourceName, device, "control_temperature",
                (flags19 >> 6) & 0x01u, ts);
            add(out, sourceName, device, "control_revs",
                (flags19 >> 7) & 0x01u, ts);
            add(out, sourceName, device, "time_ms", readLe32(p + 20), ts);
        }
    }
    return true;
}

} // namespace telemetry::protocol
