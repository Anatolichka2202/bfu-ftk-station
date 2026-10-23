#include "model/packet_journal_model.h"

#include "protocol/ethernet_udp_parser.h"
#include "protocol/source_registry.h"

#include <QDateTime>
#include <QStringList>

#include <algorithm>
#include <utility>

namespace telemetry::ui {
namespace {

QString macText(const std::uint8_t* mac) {
    QStringList parts;
    for (int i = 0; i < 6; ++i) {
        parts << QStringLiteral("%1")
                     .arg(static_cast<qulonglong>(mac[i]), 2, 16, QLatin1Char('0')).toUpper();
    }
    return parts.join(QLatin1Char(':'));
}

QString ipv4Text(std::uint32_t value) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((value >> 24) & 255U).arg((value >> 16) & 255U)
        .arg((value >> 8) & 255U).arg(value & 255U);
}

std::uint16_t be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((std::uint16_t(p[0]) << 8) | p[1]);
}

std::uint32_t be32(const std::uint8_t* p) {
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
           (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
}

QString subscriberName(const protocol::MacAddress& mac, QString& key) {
    const auto source = protocol::classifySource(mac);
    if (!source) return macText(mac.data());

    key = QString::fromUtf8(source->name.data(),
                            static_cast<int>(source->name.size()));
    if (source->block == "БСУ:ФТК") {
        return QStringLiteral("БСУ ФТК (имитатор) / ") +
            QString::fromUtf8(source->cell.data(),
                              static_cast<int>(source->cell.size()));
    }
    return QString::fromUtf8(source->block.data(),
                             static_cast<int>(source->block.size())) +
           QStringLiteral(" / ") +
           QString::fromUtf8(source->cell.data(),
                             static_cast<int>(source->cell.size()));
}

} // namespace

PacketJournalModel::PacketJournalModel(PacketJournalQueue& queue,
                                       QObject* parent)
    : QAbstractTableModel(parent), queue_(queue) {
    records_.reserve(kMaxVisibleRecords);
}

int PacketJournalModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : records_.size();
}

int PacketJournalModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant PacketJournalModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= records_.size())
        return {};

    const auto& record = records_[index.row()];

    if (role == SourceKeyRole) return record.srcKey;
    if (role == DestinationKeyRole) return record.dstKey;
    if (role == Qt::ToolTipRole) {
        if (record.packet.bytes.size() >= 12) {
            return QStringLiteral("MAC: %1 → %2")
                .arg(macText(record.packet.bytes.data() + 6),
                     macText(record.packet.bytes.data()));
        }
        return QStringLiteral("Усечённый Ethernet-кадр");
    }
    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
    case Timestamp:
        return QDateTime::fromMSecsSinceEpoch(
                   record.packet.captureTimestampNs / 1'000'000LL)
            .toString(QStringLiteral("HH:mm:ss.zzz"));
    case Source: return record.src;
    case Destination: return record.dst;
    case Protocol: return record.protocol;
    case SourceEndpoint: return record.srcEndpoint;
    case DestinationEndpoint: return record.dstEndpoint;
    case Length: return record.packet.wireLength;
    default: return {};
    }
}

QVariant PacketJournalModel::headerData(int column,
                                        Qt::Orientation orientation,
                                        int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (column) {
    case Timestamp: return QStringLiteral("Время");
    case Source: return QStringLiteral("От кого");
    case Destination: return QStringLiteral("Кому");
    case Protocol: return QStringLiteral("Протокол");
    case SourceEndpoint: return QStringLiteral("IP:порт отправителя");
    case DestinationEndpoint: return QStringLiteral("IP:порт получателя");
    case Length: return QStringLiteral("Байт");
    default: return {};
    }
}

PacketJournalModel::Record PacketJournalModel::describe(RawPacket packet) {
    Record result;
    result.packet = std::move(packet);
    const auto& bytes = result.packet.bytes;

    if (bytes.size() < 14) {
        result.src = QStringLiteral("—");
        result.dst = QStringLiteral("—");
        result.protocol = QStringLiteral("Усечённый Ethernet");
        return result;
    }

    protocol::MacAddress srcMac{};
    protocol::MacAddress dstMac{};
    std::copy_n(bytes.data(), 6, dstMac.begin());
    std::copy_n(bytes.data() + 6, 6, srcMac.begin());

    result.src = subscriberName(srcMac, result.srcKey);
    result.dst = subscriberName(dstMac, result.dstKey);

    auto ethertype = be16(bytes.data() + 12);
    std::size_t offset = 14;
    bool vlan = false;
    while ((ethertype == 0x8100 || ethertype == 0x88A8) &&
           bytes.size() >= offset + 4) {
        vlan = true;
        ethertype = be16(bytes.data() + offset + 2);
        offset += 4;
    }

    switch (ethertype) {
    case 0x0800: result.protocol = QStringLiteral("IPv4"); break;
    case 0x0806: result.protocol = QStringLiteral("ARP"); break;
    case 0x86DD: result.protocol = QStringLiteral("IPv6"); break;
    case 0x88CC: result.protocol = QStringLiteral("LLDP"); break;
    default:
        result.protocol = QStringLiteral("EtherType 0x%1")
            .arg(ethertype, 4, 16, QLatin1Char('0')).toUpper();
    }

    if (vlan) result.protocol.prepend(QStringLiteral("VLAN / "));

    if (ethertype == 0x0800 && bytes.size() >= offset + 20) {
        const auto* ip = bytes.data() + offset;
        const auto ihl = static_cast<std::size_t>((ip[0] & 0x0FU) * 4U);
        if ((ip[0] >> 4) == 4 && ihl >= 20 &&
            bytes.size() >= offset + ihl) {
            result.srcEndpoint = ipv4Text(be32(ip + 12));
            result.dstEndpoint = ipv4Text(be32(ip + 16));
            const bool firstFragment = (be16(ip + 6) & 0x1FFFU) == 0;
            if ((ip[9] == 17 || ip[9] == 6) && firstFragment &&
                bytes.size() >= offset + ihl + 4) {
                const auto* ports = ip + ihl;
                result.srcEndpoint += QStringLiteral(":%1")
                    .arg(be16(ports));
                result.dstEndpoint += QStringLiteral(":%1")
                    .arg(be16(ports + 2));
                result.protocol += ip[9] == 17
                    ? QStringLiteral(" / UDP")
                    : QStringLiteral(" / TCP");
            }
        }
    }
    return result;
}

void PacketJournalModel::drain() {
    QVector<Record> incoming;
    incoming.reserve(kMaxPacketsPerDrain);

    RawPacket packet;
    while (incoming.size() < kMaxPacketsPerDrain && queue_.tryPop(packet)) {
        incoming.push_back(describe(std::move(packet)));
    }
    if (incoming.isEmpty()) return;

    receivedCount_ += static_cast<quint64>(incoming.size());

    const int removeCount = std::max(
        0, records_.size() + incoming.size() - kMaxVisibleRecords);
    if (removeCount > 0) {
        beginRemoveRows({}, 0, removeCount - 1);
        records_.remove(0, removeCount);
        endRemoveRows();
    }

    const int first = records_.size();
    beginInsertRows({}, first, first + incoming.size() - 1);
    for (auto& item : incoming) records_.push_back(std::move(item));
    endInsertRows();
}

void PacketJournalModel::clear() {
    if (!records_.isEmpty()) {
        beginResetModel();
        records_.clear();
        endResetModel();
    }
}

QString PacketJournalModel::packetDetails(int row) const {
    if (row < 0 || row >= records_.size()) return {};
    const auto& record = records_[row];
    const auto& packet = record.packet;

    QString details = QStringLiteral(
        "Источник: %1\nНазначение: %2\nПротокол: %3\n"
        "Отправитель: %4\nПолучатель: %5\n"
        "Время захвата (ns Unix): %6\n"
        "Захвачено: %7 байт   На линии: %8 байт\n\nHEX / ASCII:\n")
        .arg(record.src, record.dst, record.protocol,
             record.srcEndpoint, record.dstEndpoint)
        .arg(packet.captureTimestampNs)
        .arg(packet.capturedLength)
        .arg(packet.wireLength);

    const auto& bytes = packet.bytes;
    for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
        const auto end = std::min(offset + 16, bytes.size());
        details += QStringLiteral("%1  ")
            .arg(static_cast<qulonglong>(offset), 6, 16,
                 QLatin1Char('0')).toUpper();

        QString hex;
        QString ascii;
        for (std::size_t i = offset; i < offset + 16; ++i) {
            if (i < end) {
                const auto b = bytes[i];
                hex += QStringLiteral("%1 ")
                    .arg(static_cast<qulonglong>(b), 2, 16, QLatin1Char('0')).toUpper();
                ascii += (b >= 32 && b < 127)
                    ? QChar(static_cast<char>(b))
                    : QLatin1Char('.');
            } else {
                hex += QStringLiteral("   ");
            }
        }
        details += hex + QStringLiteral(" |") + ascii +
                   QLatin1Char('\n');
    }
    return details;
}

} // namespace telemetry::ui
