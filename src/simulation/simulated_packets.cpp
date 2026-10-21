#include "simulation/simulated_packets.h"

#include "protocol/crc16.h"
#include "protocol/kasupp_decoder.h"
#include "protocol/yls_yaz_decoder.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace telemetry::simulation {
namespace {

using Mac = std::array<std::uint8_t, 6>;

constexpr Mac kBroadcast{0xff,0xff,0xff,0xff,0xff,0xff};
constexpr Mac kBcvmMac{0x42,0x56,0x15,0xcb,0xbe,0xbd};
constexpr Mac kKasuppMac{0x42,0x71,0x63,0x96,0xec,0x8f};
constexpr Mac kYlsMac{0x42,0x84,0x79,0x7c,0xa8,0x4e};
constexpr Mac kYnpMac{0x02,0x59,0x4e,0x50,0x00,0x01};

constexpr std::uint32_t ip(std::uint8_t a, std::uint8_t b,
                           std::uint8_t c, std::uint8_t d) {
    return (std::uint32_t(a) << 24) | (std::uint32_t(b) << 16) |
           (std::uint32_t(c) << 8) | std::uint32_t(d);
}

void be16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}
void be32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}
void le32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}
void le64(std::uint8_t* p, std::uint64_t v) {
    le32(p, static_cast<std::uint32_t>(v));
    le32(p + 4, static_cast<std::uint32_t>(v >> 32));
}
void leFloat(std::uint8_t* p, float v) {
    le32(p, std::bit_cast<std::uint32_t>(v));
}
void leDouble(std::uint8_t* p, double v) {
    le64(p, std::bit_cast<std::uint64_t>(v));
}

std::uint16_t ipChecksum(const std::uint8_t* p, std::size_t size) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < size; i += 2) {
        sum += static_cast<std::uint16_t>(
            (std::uint16_t(p[i]) << 8) |
            (i + 1 < size ? p[i + 1] : 0));
        while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

RawPacket wrapUdp(const Mac& srcMac, std::uint32_t srcIp,
                  std::uint32_t dstIp, std::uint16_t srcPort,
                  std::uint16_t dstPort,
                  std::span<const std::uint8_t> payload,
                  std::int64_t ts) {
    RawPacket packet;
    packet.captureTimestampNs = ts;
    packet.bytes.assign(14 + 20 + 8 + payload.size(), 0);

    auto* f = packet.bytes.data();
    std::copy(kBroadcast.begin(), kBroadcast.end(), f);
    std::copy(srcMac.begin(), srcMac.end(), f + 6);
    f[12] = 0x08; f[13] = 0x00;

    auto* iph = f + 14;
    iph[0] = 0x45;
    const auto ipLen = static_cast<std::uint16_t>(20 + 8 + payload.size());
    be16(iph + 2, ipLen);
    iph[8] = 64;
    iph[9] = 17;
    be32(iph + 12, srcIp);
    be32(iph + 16, dstIp);
    be16(iph + 10, ipChecksum(iph, 20));

    auto* udp = iph + 20;
    be16(udp, srcPort);
    be16(udp + 2, dstPort);
    be16(udp + 4, static_cast<std::uint16_t>(8 + payload.size()));
    std::copy(payload.begin(), payload.end(), udp + 8);

    packet.capturedLength = static_cast<std::uint32_t>(packet.bytes.size());
    packet.wireLength = packet.capturedLength;
    return packet;
}

std::vector<std::uint8_t> bcvmPayload(std::uint32_t counter) {
    std::vector<std::uint8_t> p(protocol::kBcvmPagedSize, 0);
    be32(p.data(), counter);
    p[4] = protocol::kKasuppProtocolVersion;
    p[5] = static_cast<std::uint8_t>(5U << 5); // READY
    be32(p.data() + 6, counter);

    const auto page = protocol::bcvmPageFromPacketCounter(counter);
    if (page == 1U) {
        p[13] = static_cast<std::uint8_t>((counter / 10U) & 0xffU);
        const char date[] = "20261021";
        const char time[] = "00043200";
        std::copy_n(reinterpret_cast<const std::uint8_t*>(date), 8, p.data()+14);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(time), 8, p.data()+22);
        for (std::size_t i=0;i<40;i++) p[30+i]=static_cast<std::uint8_t>(i+1);
        for (std::size_t i=0;i<100;i++) p[70+i]=static_cast<std::uint8_t>(counter+i);
        for (std::size_t i=0;i<42;i++) p[170+i]=static_cast<std::uint8_t>((counter/20+i)&0xff);
        for (std::size_t i=0;i<58;i++) {
            p[212+i]=static_cast<std::uint8_t>(0x20U+(i&0x3fU));
            p[270+i]=static_cast<std::uint8_t>(0x60U+(i&0x3fU));
        }
        for (std::size_t i=0;i<144;i++) p[328+i]=static_cast<std::uint8_t>((i+counter/5U)&0xff);
    } else if (page == 2U) {
        for (std::size_t i=0;i<240;i++) p[10+i]=static_cast<std::uint8_t>((0x30U+i+counter/10U)&0xff);
        // MNP B intentionally remains zero: receiver B is not installed.
    } else if (page == 3U || page == 4U) {
        for (std::size_t i=0;i<72;i++) p[10+i]=static_cast<std::uint8_t>((page*16U+i+counter/10U)&0xff);
    } else if (page == 5U) {
        for (std::size_t i=0;i<100;i++) p[10+i]=static_cast<std::uint8_t>((0x80U+i+counter)&0xff);
    }

    protocol::writeTrailingCrc16Be(p, protocol::kBcvmPagedCrcOffset);
    return p;
}

std::vector<std::uint8_t> kasuppPayload(std::uint32_t counter) {
    std::vector<std::uint8_t> p(protocol::kKasuppNormalSize, 0);
    be32(p.data(), counter);
    p[4] = protocol::kKasuppProtocolVersion;
    p[5] = 0x00;
    p[6] = 0x00;
    protocol::writeTrailingCrc16Be(p, protocol::kKasuppNormalCrcOffset);
    return p;
}

std::vector<std::uint8_t> ylsPayload(std::uint32_t counter) {
    std::vector<std::uint8_t> p(protocol::kExpectedYlsPayloadSize, 0);
    for (std::size_t bkd=0;bkd<protocol::kBkdCount;bkd++) {
        for (std::size_t yaz=0;yaz<protocol::kYazPerBkd;yaz++) {
            const auto idx=bkd*protocol::kYazPerBkd+yaz;
            auto* r=p.data()+protocol::kYlsYazDataOffset+
                    idx*protocol::kYazRecordSize;
            for (int n=0;n<9;n++) {
                const auto v=static_cast<std::uint16_t>(
                    1000U + bkd*100U + yaz*10U + n + counter/10U);
                r[n*2]=static_cast<std::uint8_t>(v);
                r[n*2+1]=static_cast<std::uint8_t>(v>>8);
            }
            r[18]=static_cast<std::uint8_t>((counter/25U + idx)&0xffU);
            r[19]=0xD7U;
            le32(r+20,counter*10U);
        }
    }
    return p;
}

template <std::size_t N>
std::array<std::uint8_t,N> pattern(std::uint8_t frameId,
                                   std::uint32_t epoch) {
    std::array<std::uint8_t,N> out{};
    for (std::size_t i=0;i<N;i++)
        out[i]=static_cast<std::uint8_t>(frameId+i+epoch);
    return out;
}

void copyPart(std::span<std::uint8_t> dst, std::size_t dstOff,
              std::span<const std::uint8_t> src,
              std::size_t srcOff, std::size_t count) {
    std::copy_n(src.begin()+static_cast<std::ptrdiff_t>(srcOff),
                count,
                dst.begin()+static_cast<std::ptrdiff_t>(dstOff));
}

std::vector<std::uint8_t> ynpPayload(std::uint32_t counter) {
    std::vector<std::uint8_t> p(512,0);
    const auto utc=(12U*3600U*1000U + counter*10U)%(24U*3600U*1000U);
    le32(p.data()+0,counter);
    le32(p.data()+4,utc);
    leFloat(p.data()+8,10.0F + float(counter%100U)/100.0F);
    leFloat(p.data()+12,1.5F);
    leFloat(p.data()+16,-0.2F);
    leFloat(p.data()+20,0.01F);
    leFloat(p.data()+24,0.02F);
    leFloat(p.data()+28,0.03F);
    leFloat(p.data()+32,0.1F);
    leFloat(p.data()+36,0.2F);
    leFloat(p.data()+40,9.7F);
    leFloat(p.data()+44,0.9F);
    leFloat(p.data()+48,0.7F);
    leFloat(p.data()+52,-0.1F);
    leDouble(p.data()+56,0.9);
    leDouble(p.data()+64,0.7);
    leDouble(p.data()+72,123.5);
    le32(p.data()+80,0x0000001FU);
    le32(p.data()+84,20261021U);
    le32(p.data()+88,counter%100U*10U);
    le32(p.data()+92,18U);
    le32(p.data()+96,1U);

    auto diag=std::span<std::uint8_t>(p).subspan(100,412);
    const auto page=counter%18U;
    if ((page&1U)!=0U) return p; // MNP B absent.

    const auto cycleStart=counter-(counter%18U);
    const auto navEpoch=cycleStart/100U;
    const auto slowEpoch=cycleStart/400U;
    const auto f3000=pattern<160>(0x30,navEpoch);
    const auto f3111=pattern<1344>(0x31,navEpoch);
    const auto f3400=pattern<512>(0x40,slowEpoch);
    const auto f3401=pattern<384>(0x41,slowEpoch);
    const auto f3402=pattern<512>(0x42,slowEpoch);
    const std::array<std::uint8_t,512> f3403{}; // output not confirmed
    const auto f3406=pattern<80>(0x46,slowEpoch);

    switch(page) {
    case 0:
        copyPart(diag,0,f3000,0,160);
        copyPart(diag,160,f3406,0,80);
        break;
    case 2:
        copyPart(diag,0,f3400,0,412);
        break;
    case 4:
        copyPart(diag,0,f3400,412,100);
        copyPart(diag,100,f3402,0,312);
        break;
    case 6:
        copyPart(diag,0,f3402,312,200);
        copyPart(diag,200,f3403,0,212);
        break;
    case 8:
        copyPart(diag,0,f3403,212,300);
        copyPart(diag,300,f3111,0,112);
        break;
    case 10:
        copyPart(diag,0,f3111,112,412);
        break;
    case 12:
        copyPart(diag,0,f3111,524,412);
        break;
    case 14:
        copyPart(diag,0,f3111,936,408);
        break;
    case 16:
        copyPart(diag,0,f3401,0,384);
        break;
    default:
        break;
    }
    return p;
}

} // namespace

std::vector<RawPacket> makeSimulationTick(
    std::uint32_t counter, std::int64_t ts) {
    std::vector<RawPacket> out;
    out.reserve(4);

    const auto bcvm=bcvmPayload(counter);
    out.push_back(wrapUdp(kBcvmMac,ip(192,168,17,231),
                          ip(192,168,17,246),101,206,bcvm,ts));

    const auto kasu=kasuppPayload(counter);
    out.push_back(wrapUdp(kKasuppMac,ip(192,168,17,246),
                          ip(192,168,17,231),206,101,kasu,ts));

    const auto yls=ylsPayload(counter);
    out.push_back(wrapUdp(kYlsMac,ip(192,168,17,235),
                          ip(192,168,17,246),180,206,yls,ts));

    const auto ynp=ynpPayload(counter);
    out.push_back(wrapUdp(kYnpMac,ip(192,168,17,240),
                          ip(192,168,17,246),200,100,ynp,ts));

    return out;
}

} // namespace telemetry::simulation
