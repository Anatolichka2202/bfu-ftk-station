#include "protocol/source_registry.h"

#include <cstdio>
#include <sstream>

namespace telemetry::protocol {
namespace {

// Source: "Список_IP_MAC(1).docx", current project inputs (28.09.2026).
constexpr SourceDescriptor kSources[] = {
    {{0x42,0x56,0x15,0xCB,0xBE,0xBD}, SourceKind::Bcvm,   "BCVM.YV1"},
    {{0x42,0x50,0x27,0xE5,0xEF,0x2B}, SourceKind::Bcvm,   "BCVM.YV2"},
    {{0x42,0x71,0x63,0x96,0xEC,0x8F}, SourceKind::Kasupp, "KASUPP.ETH1"},
    {{0x42,0x2A,0xF9,0xD1,0xF2,0x1B}, SourceKind::Kasupp, "KASUPP.ETH2"},

    // YLS candidates from both networks/blocks. Decoder additionally requires
    // a YLS payload large enough to contain yaz_data.
    {{0x42,0x93,0x6A,0xB2,0x28,0xC0}, SourceKind::Yls, "BKPO-B.YLS.ETH1"},
    {{0x42,0xCF,0x9D,0xEA,0xC4,0x24}, SourceKind::Yls, "BKPO-B.YLS.ETH2"},
    {{0x42,0x84,0x79,0x7C,0xA8,0x4E}, SourceKind::Yls, "BSU-FTK.YLS.ETH1"},
    {{0x42,0x42,0x30,0xC4,0x06,0x5B}, SourceKind::Yls, "BSU-FTK.YLS.ETH2"},
    {{0x42,0xF3,0xAF,0x15,0xF9,0xF9}, SourceKind::Yls, "BKPO-A.YLS.ETH1"},
    {{0x42,0x9C,0x34,0xB6,0x8D,0x6F}, SourceKind::Yls, "BKPO-A.YLS.ETH2"},
    {{0x42,0x06,0xE0,0xF3,0x83,0x32}, SourceKind::Yls, "BKMBO-A.YLS.ETH1"},
    {{0x42,0xA7,0x14,0x6B,0x43,0xF2}, SourceKind::Yls, "BKMBO-A.YLS.ETH2"},
    {{0x42,0x35,0xA7,0x2F,0xA1,0xD9}, SourceKind::Yls, "BKHO-A.YLS.ETH1"},
    {{0x42,0x3B,0x6D,0xA2,0x82,0x85}, SourceKind::Yls, "BKHO-A.YLS.ETH2"},
};

std::string macText(const MacAddress& mac) {
    char out[18]{};
    std::snprintf(out, sizeof(out), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return out;
}

} // namespace

std::span<const SourceDescriptor> knownSources() noexcept {
    return kSources;
}

std::optional<SourceDescriptor> classifySource(const MacAddress& mac) noexcept {
    for (const auto& source : kSources) {
        if (source.mac == mac) {
            return source;
        }
    }
    return std::nullopt;
}

std::string buildCaptureFilter() {
    std::ostringstream filter;
    filter << "ether broadcast and udp and (";
    bool first = true;
    for (const auto& source : kSources) {
        if (!first) filter << " or ";
        first = false;
        filter << "ether src " << macText(source.mac);
    }
    filter << ')';
    return filter.str();
}

} // namespace telemetry::protocol
