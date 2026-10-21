#include "model/telemetry_table_model.h"

#include <QSet>

#include <algorithm>
#include <utility>

namespace telemetry::ui {
namespace {

constexpr int kMaxBatchesPerDrain = 64;

} // namespace

TelemetryTableModel::TelemetryTableModel(BatchQueue& input, QObject* parent)
    : QAbstractTableModel(parent), input_(input) {}

int TelemetryTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : rows_.size();
}

int TelemetryTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant TelemetryTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rows_.size())
        return {};

    const auto& row = rows_[index.row()];

    if (role == Qt::ToolTipRole) {
        return QStringLiteral("Capture timestamp: %1 ns").arg(row.timestampNs);
    }

    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
    case Source:
        return row.source;
    case Device:
        return row.device;
    case Parameter:
        return row.parameter;
    case RawValue:
        return QVariant::fromValue<qulonglong>(row.raw);
    case AgeMs: {
        const auto ageNs =
            std::max<qint64>(0, newestTimestampNs_ - row.timestampNs);
        return QVariant::fromValue<qlonglong>(ageNs / 1'000'000LL);
    }
    default:
        return {};
    }
}

QVariant TelemetryTableModel::headerData(int section,
                                         Qt::Orientation orientation,
                                         int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};

    switch (section) {
    case Source:
        return QStringLiteral("Источник");
    case Device:
        return QStringLiteral("Устройство");
    case Parameter:
        return QStringLiteral("Параметр");
    case RawValue:
        return QStringLiteral("Код");
    case AgeMs:
        return QStringLiteral("Возраст, мс");
    default:
        return {};
    }
}

QString TelemetryTableModel::keyFor(const TelemetryValue& value) {
    return QString::fromStdString(value.sourceName) + QLatin1Char('|') +
           QString::fromStdString(value.device) + QLatin1Char('|') +
           QString::fromStdString(value.parameter);
}

void TelemetryTableModel::drain() {
    TelemetryBatch batch;
    TelemetryBatch merged;
    QHash<QString, int> mergedByKey;
    int drained = 0;

    while (drained < kMaxBatchesPerDrain && input_.tryPop(batch)) {
        merged.captureTimestampNs =
            std::max(merged.captureTimestampNs, batch.captureTimestampNs);

        for (auto& value : batch.values) {
            const auto key = keyFor(value);
            const auto it = mergedByKey.constFind(key);
            if (it == mergedByKey.cend()) {
                mergedByKey.insert(
                    key, static_cast<int>(merged.values.size()));
                merged.values.push_back(std::move(value));
            } else {
                merged.values[static_cast<std::size_t>(it.value())] =
                    std::move(value);
            }
        }
        ++drained;
    }

    if (!merged.values.empty()) applyBatch(merged);
}

void TelemetryTableModel::applyBatch(const TelemetryBatch& batch) {
    newestTimestampNs_ =
        std::max(newestTimestampNs_,
                 static_cast<qint64>(batch.captureTimestampNs));

    QVector<const TelemetryValue*> missing;
    missing.reserve(static_cast<int>(batch.values.size()));
    QSet<QString> pendingKeys;

    for (const auto& value : batch.values) {
        const auto key = keyFor(value);
        if (!rowByKey_.contains(key) && !pendingKeys.contains(key)) {
            pendingKeys.insert(key);
            missing.push_back(&value);
        }
    }

    if (!missing.isEmpty()) {
        const int first = rows_.size();
        const int last = first + missing.size() - 1;
        beginInsertRows({}, first, last);

        for (const auto* value : missing) {
            const auto key = keyFor(*value);
            rowByKey_.insert(key, rows_.size());
            rows_.push_back({
                QString::fromStdString(value->sourceName),
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
        emit dataChanged(index(minRow, RawValue), index(maxRow, AgeMs),
                         {Qt::DisplayRole, Qt::ToolTipRole});
    }

    if (!rows_.isEmpty()) {
        emit dataChanged(index(0, AgeMs),
                         index(rows_.size() - 1, AgeMs),
                         {Qt::DisplayRole});
    }
}

} // namespace telemetry::ui
