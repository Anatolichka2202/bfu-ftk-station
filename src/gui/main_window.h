#pragma once

#include "capture/capture_service.h"
#include "model/telemetry_table_model.h"
#include "telemetry/decoder_service.h"

#include <QMainWindow>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSortFilterProxyModel;
class QTableView;
class QTimer;

namespace telemetry::ui {

class MainWindow final : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(CaptureService& capture, DecoderService& decoder,
               TelemetryTableModel& model, QWidget* parent = nullptr);

private slots:
    void refreshDevices();
    void startCapture();
    void stopCapture();
    void updateStatus();

private:
    CaptureService& capture_;
    DecoderService& decoder_;
    TelemetryTableModel& model_;

    QComboBox* devices_{};
    QPushButton* start_{};
    QPushButton* stop_{};
    QLineEdit* filter_{};
    QLabel* status_{};
    QSortFilterProxyModel* proxy_{};
    QTableView* table_{};
    QTimer* drainTimer_{};
    QTimer* statusTimer_{};
};

} // namespace telemetry::ui
