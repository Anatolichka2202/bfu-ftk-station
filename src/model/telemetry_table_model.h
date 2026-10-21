#pragma once

#include "telemetry/decoder_service.h"

#include <QAbstractTableModel>
#include <QHash>
#include <QString>
#include <QVector>

namespace telemetry::ui {

class TelemetryTableModel final : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Source, Device, Parameter, RawValue, AgeMs, ColumnCount };

    explicit TelemetryTableModel(BatchQueue& input, QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role) const override;

public slots:
    void drain();

private:
    struct Row {
        QString source;
        QString device;
        QString parameter;
        quint64 raw{};
        qint64 timestampNs{};
    };

    static QString keyFor(const TelemetryValue& value);
    void applyBatch(const TelemetryBatch& batch);

    BatchQueue& input_;
    QVector<Row> rows_;
    QHash<QString, int> rowByKey_;
    qint64 newestTimestampNs_{};
};

} // namespace telemetry::ui
