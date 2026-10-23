#pragma once

#include "capture/capture_service.h"
#include "model/telemetry_table_model.h"
#include "model/packet_journal_model.h"
#include "simulation/simulation_service.h"
#include "telemetry/decoder_service.h"

#include <QElapsedTimer>
#include <QMainWindow>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSortFilterProxyModel;
class QTableView;
class QPlainTextEdit;
class QTimer;
class QTreeWidget;

namespace telemetry::ui {

class MainWindow final : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(CaptureService& capture,
               simulation::SimulationService& simulation,
               DecoderService& decoder,
               TelemetryTableModel& model,
               PacketJournalModel& journal,
               QWidget* parent = nullptr);

private slots:
    void refreshDevices();
    void startCapture();
    void stopCapture();
    void updateStatus();
    void applySourceFilter();
    void updateInputMode();

private:
    bool simulationMode() const;
    void buildSourceTree();
    void setCaptureState(const QString& text, const char* state);

    CaptureService& capture_;
    simulation::SimulationService& simulation_;
    DecoderService& decoder_;
    TelemetryTableModel& model_;
    PacketJournalModel& journal_;

    QComboBox* inputMode_{};
    QComboBox* devices_{};
    QPushButton* refreshDevices_{};
    QPushButton* start_{};
    QPushButton* stop_{};
    QLineEdit* filter_{};
    QLabel* captureState_{};
    QLabel* rxValue_{};
    QLabel* dropValue_{};
    QLabel* decodedValue_{};
    QLabel* errorValue_{};
    QLabel* activityValue_{};
    QLabel* diagnostics_{};
    QTreeWidget* sources_{};
    QSortFilterProxyModel* proxy_{};
    QTableView* table_{};
    QSortFilterProxyModel* packetProxy_{};
    QTableView* packetsTable_{};
    QLineEdit* packetFilter_{};
    QPlainTextEdit* packetDetails_{};
    QTimer* drainTimer_{};
    QTimer* statusTimer_{};

    quint64 lastCaptured_{};
    QElapsedTimer activityTimer_;
    bool activitySeen_{false};
};

} // namespace telemetry::ui
