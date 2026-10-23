#include "protocol/source_registry.h"

namespace telemetry::protocol {
namespace {

constexpr std::uint32_t ip(std::uint8_t a, std::uint8_t b,
                           std::uint8_t c, std::uint8_t d) noexcept {
    return (static_cast<std::uint32_t>(a) << 24) |
           (static_cast<std::uint32_t>(b) << 16) |
           (static_cast<std::uint32_t>(c) << 8) |
            static_cast<std::uint32_t>(d);
}

constexpr SourceDescriptor kSources[] = {
    // Ступень Б
    {{0x42,0xD4,0x9D,0xB8,0xB7,0x5E}, SourceKind::Ynp,
     "B.ASN.YNP1", "СТУПЕНЬ Б", "АСН", "ЯНП1",
     ip(192,168,17,230), 100, false},
    {{0x42,0xE9,0x4F,0xAE,0xD0,0x45}, SourceKind::Ynp,
     "B.ASN.YNP2", "СТУПЕНЬ Б", "АСН", "ЯНП2",
     ip(192,168,17,230), 100, false},

    {{0x42,0x56,0x15,0xCB,0xBE,0xBD}, SourceKind::Bcvm,
     "B.BCVM.YV1", "СТУПЕНЬ Б", "БЦВМ", "ЯВ1",
     ip(192,168,17,231), 101, false},
    {{0x42,0x50,0x27,0xE5,0xEF,0x2B}, SourceKind::Bcvm,
     "B.BCVM.YV2", "СТУПЕНЬ Б", "БЦВМ", "ЯВ2",
     ip(192,168,17,231), 101, false},

    {{0x42,0x93,0x6A,0xB2,0x28,0xC0}, SourceKind::Yls,
     "B.BKPO-B.YLS.ETH1", "СТУПЕНЬ Б", "БКПО:Б", "ЯЛС ETH1",
     ip(192,168,17,232), 102, false},
    {{0x42,0xCF,0x9D,0xEA,0xC4,0x24}, SourceKind::Yls,
     "B.BKPO-B.YLS.ETH2", "СТУПЕНЬ Б", "БКПО:Б", "ЯЛС ETH2",
     ip(192,168,17,232), 102, false},

    {{0x42,0x7F,0x1C,0xA9,0x1C,0x45}, SourceKind::Raw,
     "B.SEP-B.ETH1", "СТУПЕНЬ Б", "СЕП:Б", "ETH1",
     ip(192,168,17,233), 103, false},
    {{0x42,0x5A,0xC2,0xA2,0x9A,0xF9}, SourceKind::Raw,
     "B.SEP-B.ETH2", "СТУПЕНЬ Б", "СЕП:Б", "ETH2",
     ip(192,168,17,233), 103, false},

    {{0x42,0x84,0x79,0x7C,0xA8,0x4E}, SourceKind::Yls,
     "B.BSU-FTK.YLS.ETH1", "СТУПЕНЬ Б", "БСУ:ФТК", "ЯЛС ETH1",
     ip(192,168,17,234), 104, false},
    {{0x42,0x42,0x30,0xC4,0x06,0x5B}, SourceKind::Yls,
     "B.BSU-FTK.YLS.ETH2", "СТУПЕНЬ Б", "БСУ:ФТК", "ЯЛС ETH2",
     ip(192,168,17,234), 104, false},

    {{0x42,0x97,0x65,0xB5,0x56,0xED}, SourceKind::Raw,
     "B.BSM-AP.YSK1", "СТУПЕНЬ Б", "БСМ (точка доступа)", "ЯСК1",
     ip(192,168,17,235), 105, false},
    {{0x42,0x01,0x0C,0x5A,0x8B,0x95}, SourceKind::Raw,
     "B.BSM-AP.YSK2", "СТУПЕНЬ Б", "БСМ (точка доступа)", "ЯСК2",
     ip(192,168,17,235), 105, false},

    // Ступень А
    {{0x42,0xF3,0xAF,0x15,0xF9,0xF9}, SourceKind::Yls,
     "A.BKPO-A.YLS.ETH1", "СТУПЕНЬ А", "БКПО:А", "ЯЛС ETH1",
     ip(192,168,17,236), 201, false},
    {{0x42,0x9C,0x34,0xB6,0x8D,0x6F}, SourceKind::Yls,
     "A.BKPO-A.YLS.ETH2", "СТУПЕНЬ А", "БКПО:А", "ЯЛС ETH2",
     ip(192,168,17,236), 201, false},

    {{0x42,0x06,0xE0,0xF3,0x83,0x32}, SourceKind::Yls,
     "A.BKMBO-A.YLS.ETH1", "СТУПЕНЬ А", "БКМБО:А", "ЯЛС ETH1",
     ip(192,168,17,237), 202, false},
    {{0x42,0xA7,0x14,0x6B,0x43,0xF2}, SourceKind::Yls,
     "A.BKMBO-A.YLS.ETH2", "СТУПЕНЬ А", "БКМБО:А", "ЯЛС ETH2",
     ip(192,168,17,237), 202, false},

    {{0x42,0x7D,0x3C,0x1D,0xED,0xA5}, SourceKind::Raw,
     "A.SEP-A.ETH1", "СТУПЕНЬ А", "СЭП:А", "ETH1",
     ip(192,168,17,238), 203, false},
    {{0x42,0xFD,0x57,0x2A,0x5A,0xB6}, SourceKind::Raw,
     "A.SEP-A.ETH2", "СТУПЕНЬ А", "СЭП:А", "ETH2",
     ip(192,168,17,238), 203, false},

    {{0x42,0x35,0xA7,0x2F,0xA1,0xD9}, SourceKind::Yls,
     "A.BKHO-A.YLS.ETH1", "СТУПЕНЬ А", "БКХО:А", "ЯЛС ETH1",
     ip(192,168,17,239), 204, false},
    {{0x42,0x3B,0x6D,0xA2,0x82,0x85}, SourceKind::Yls,
     "A.BKHO-A.YLS.ETH2", "СТУПЕНЬ А", "БКХО:А", "ЯЛС ETH2",
     ip(192,168,17,239), 204, false},

    {{0x42,0x9E,0x70,0xB6,0xC3,0x29}, SourceKind::Raw,
     "A.BSM-CLIENT.YSK1", "СТУПЕНЬ А", "БСМ (клиент)", "ЯСК1",
     ip(192,168,17,240), 205, false},
    {{0x42,0x2E,0x24,0x0E,0xBD,0x3A}, SourceKind::Raw,
     "A.BSM-CLIENT.YSK2", "СТУПЕНЬ А", "БСМ (клиент)", "ЯСК2",
     ip(192,168,17,241), 205, false},

    // Наземка
    {{0x42,0x71,0x63,0x96,0xEC,0x8F}, SourceKind::Kasupp,
     "GROUND.KASUPP.ETH1", "НАЗЕМКА", "КАСУ ПП", "ETH1",
     ip(192,168,17,246), 206, false},
    {{0x42,0x2A,0xF9,0xD1,0xF2,0x1B}, SourceKind::Kasupp,
     "GROUND.KASUPP.ETH2", "НАЗЕМКА", "КАСУ ПП", "ETH2",
     ip(192,168,17,246), 206, false},

    // Резерв MAC — IP/порт не назначены.
    {{0x42,0x23,0x76,0xE1,0x05,0x56}, SourceKind::Raw,
     "RESERVE.MAC01", "РЕЗЕРВ", "Резерв MAC", "MAC01", 0, 0, true},
    {{0x42,0xE1,0x46,0x65,0xB6,0x13}, SourceKind::Raw,
     "RESERVE.MAC02", "РЕЗЕРВ", "Резерв MAC", "MAC02", 0, 0, true},
    {{0x42,0x6B,0x1C,0x48,0x5A,0x04}, SourceKind::Raw,
     "RESERVE.MAC03", "РЕЗЕРВ", "Резерв MAC", "MAC03", 0, 0, true},
    {{0x42,0x26,0x7C,0x7E,0xDC,0x59}, SourceKind::Raw,
     "RESERVE.MAC04", "РЕЗЕРВ", "Резерв MAC", "MAC04", 0, 0, true},
    {{0x42,0x30,0x52,0x5E,0x4C,0x4E}, SourceKind::Raw,
     "RESERVE.MAC05", "РЕЗЕРВ", "Резерв MAC", "MAC05", 0, 0, true},
    {{0x42,0xED,0x87,0x8F,0x3F,0xC8}, SourceKind::Raw,
     "RESERVE.MAC06", "РЕЗЕРВ", "Резерв MAC", "MAC06", 0, 0, true},
    {{0x42,0x04,0x59,0x9E,0x0A,0x17}, SourceKind::Raw,
     "RESERVE.MAC07", "РЕЗЕРВ", "Резерв MAC", "MAC07", 0, 0, true},
    {{0x42,0x2E,0x27,0xB0,0xC4,0x12}, SourceKind::Raw,
     "RESERVE.MAC08", "РЕЗЕРВ", "Резерв MAC", "MAC08", 0, 0, true},
};

} // namespace

std::span<const SourceDescriptor> knownSources() noexcept {
    return kSources;
}

std::optional<SourceDescriptor> classifySource(const MacAddress& mac) noexcept {
    for (const auto& source : kSources) {
        if (source.mac == mac) return source;
    }
    return std::nullopt;
}

std::string buildCaptureFilter() {
    // Настоящий сниффер: capture-слой не отбрасывает кадры по MAC/IP/UDP.
    return {};
}

} // namespace telemetry::protocol
