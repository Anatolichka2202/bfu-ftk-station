#pragma once

#include "telemetry/decoder_service.h"

#include <QAbstractTableModel>
#include <QString>
#include <QVector>

namespace telemetry::ui {

// Append-only bounded on-screen packet history. Does not consume or filter
// protocol-decoder output; every RawPacket passes through here independently.
class PacketJournalModel final : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Timestamp, Source, Destination, Protocol,
                  SourceEndpoint, DestinationEndpoint, Length, ColumnCount };
    enum ExtraRole { SourceKeyRole = Qt::UserRole + 1,
                     DestinationKeyRole = Qt::UserRole + 2 };

    explicit PacketJournalModel(PacketJournalQueue& queue,
                                QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role) const override;

    QString packetDetails(int row) const;
    quint64 receivedCount() const noexcept { return receivedCount_; }

public slots:
    void drain();
    void clear();

private:
    struct Record {
        RawPacket packet;
        QString src;
        QString dst;
        QString srcKey;
        QString dstKey;
        QString protocol;
        QString srcEndpoint;
        QString dstEndpoint;
    };

    static Record describe(RawPacket packet);

    PacketJournalQueue& queue_;
    QVector<Record> records_;
    quint64 receivedCount_{};
    static constexpr int kMaxVisibleRecords = 4000;
    static constexpr int kMaxPacketsPerDrain = 512;
};

} // namespace telemetry::ui
