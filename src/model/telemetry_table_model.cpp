#include "model/telemetry_table_model.h"

#include <algorithm>

namespace telemetry::ui {

TelemetryTableModel::TelemetryTableModel(BatchQueue& input, QObject* parent)
    : QAbstractTableModel(parent), input_(input) {}

int TelemetryTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : rows_.size();
}

int TelemetryTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant TelemetryTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rows_.size()) return {};
    const auto& row = rows_[index.row()];
    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
    case Source: return row.source;
    case Device: return row.device;
    case Parameter: return row.parameter;
    case RawValue: return QVariant::fromValue<qulonglong>(row.raw);
    case CaptureTimeNs: return QVariant::fromValue<qlonglong>(row.timestampNs);
    default: return {};
    }
}

QVariant TelemetryTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
    case Source: return QStringLiteral("Источник");
    case Device: return QStringLiteral("Устройство");
    case Parameter: return QStringLiteral("Параметр");
    case RawValue: return QStringLiteral("RAW");
    case CaptureTimeNs: return QStringLiteral("Capture timestamp, ns");
    default: return {};
    }
}

QString TelemetryTableModel::keyFor(const TelemetryValue& value) {
    return QString::fromStdString(value.sourceName) + QLatin1Char('|') +
           QString::fromStdString(value.device) + QLatin1Char('|') +
           QString::fromStdString(value.parameter);
}

void TelemetryTableModel::drain() {
    TelemetryBatch batch;
    while (input_.tryPop(batch)) {
        applyBatch(batch);
    }
}

void TelemetryTableModel::applyBatch(const TelemetryBatch& batch) {
    QVector<const TelemetryValue*> missing;
    missing.reserve(static_cast<int>(batch.values.size()));
    for (const auto& value : batch.values) {
        if (!rowByKey_.contains(keyFor(value))) missing.push_back(&value);
    }

    if (!missing.isEmpty()) {
        const int first = rows_.size();
        const int last = first + missing.size() - 1;
        beginInsertRows({}, first, last);
        for (const auto* value : missing) {
            const auto key = keyFor(*value);
            rowByKey_.insert(key, rows_.size());
            rows_.push_back({QString::fromStdString(value->sourceName),
                             QString::fromStdString(value->device),
                             QString::fromStdString(value->parameter),
                             static_cast<quint64>(value->rawValue),
                             static_cast<qint64>(value->captureTimestampNs)});
        }
        endInsertRows();
    }

    int minRow = rows_.size();
    int maxRow = -1;
    for (const auto& value : batch.values) {
        const auto rowIndex = rowByKey_.value(keyFor(value), -1);
        if (rowIndex < 0) continue;
        auto& row = rows_[rowIndex];
        row.raw = value.rawValue;
        row.timestampNs = value.captureTimestampNs;
        minRow = std::min(minRow, rowIndex);
        maxRow = std::max(maxRow, rowIndex);
    }
    if (maxRow >= minRow) {
        emit dataChanged(index(minRow, RawValue), index(maxRow, CaptureTimeNs), {Qt::DisplayRole});
    }
}

} // namespace telemetry::ui
