#include "gui/main_window.h"

#include "protocol/source_registry.h"

#include <QComboBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>

namespace telemetry::ui {

MainWindow::MainWindow(CaptureService& capture, DecoderService& decoder,
                       TelemetryTableModel& model, QWidget* parent)
    : QMainWindow(parent), capture_(capture), decoder_(decoder), model_(model) {
    setWindowTitle(QStringLiteral("БСУ ФТК — телеметрия"));
    resize(1250, 760);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    auto* controls = new QHBoxLayout;

    devices_ = new QComboBox(central);
    start_ = new QPushButton(QStringLiteral("Старт"), central);
    stop_ = new QPushButton(QStringLiteral("Стоп"), central);
    stop_->setEnabled(false);
    filter_ = new QLineEdit(central);
    filter_->setPlaceholderText(QStringLiteral("Фильтр по источнику / устройству / параметру"));
    status_ = new QLabel(QStringLiteral("Остановлено"), central);

    controls->addWidget(devices_, 2);
    controls->addWidget(start_);
    controls->addWidget(stop_);
    controls->addWidget(filter_, 2);
    root->addLayout(controls);
    root->addWidget(status_);

    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(&model_);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setFilterKeyColumn(-1);

    table_ = new QTableView(central);
    table_->setModel(proxy_);
    table_->setSortingEnabled(true);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(TelemetryTableModel::Source, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(TelemetryTableModel::Device, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(TelemetryTableModel::Parameter, QHeaderView::Stretch);
    root->addWidget(table_);
    setCentralWidget(central);

    connect(start_, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(stop_, &QPushButton::clicked, this, &MainWindow::stopCapture);
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    connect(filter_, &QLineEdit::textChanged, proxy_, &QSortFilterProxyModel::setFilterFixedString);
#endif

    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(33); // GUI refresh ~30 Hz; capture/decoder remain independent.
    connect(drainTimer_, &QTimer::timeout, &model_, &TelemetryTableModel::drain);
    drainTimer_->start();

    statusTimer_ = new QTimer(this);
    statusTimer_->setInterval(500);
    connect(statusTimer_, &QTimer::timeout, this, &MainWindow::updateStatus);
    statusTimer_->start();

    refreshDevices();
}

void MainWindow::refreshDevices() {
    devices_->clear();
    std::string error;
    const auto devices = CaptureService::availableDevices(error);
    for (const auto& dev : devices) {
        const auto label = dev.description.empty() ? dev.name : dev.description + " — " + dev.name;
        devices_->addItem(QString::fromStdString(label), QString::fromStdString(dev.name));
    }
    if (devices.empty() && !error.empty()) status_->setText(QString::fromStdString(error));
}

void MainWindow::startCapture() {
    if (devices_->currentIndex() < 0) return;
    std::string error;
    const auto device = devices_->currentData().toString().toStdString();
    const auto bpf = protocol::buildCaptureFilter();
    if (!capture_.start(device, bpf, error)) {
        QMessageBox::critical(this, QStringLiteral("Npcap"), QString::fromStdString(error));
        return;
    }
    start_->setEnabled(false);
    stop_->setEnabled(true);
}

void MainWindow::stopCapture() {
    capture_.stop();
    start_->setEnabled(true);
    stop_->setEnabled(false);
}

void MainWindow::updateStatus() {
    const auto cs = capture_.stats();
    const auto ds = decoder_.stats();
    status_->setText(QStringLiteral(
        "RX=%1  capture_queue_drop=%2  pcap_drop=%3  decoded=%4  parse_error=%5  batch_drop=%6")
        .arg(cs.captured).arg(cs.queueDrops).arg(cs.pcapDropped)
        .arg(ds.packetsDecoded).arg(ds.parseErrors).arg(ds.batchDrops));

    if (!capture_.running() && stop_->isEnabled()) {
        stop_->setEnabled(false);
        start_->setEnabled(true);
        const auto error = capture_.lastError();
        if (!error.empty()) status_->setText(status_->text() + QStringLiteral("  ERROR: ") + QString::fromStdString(error));
    }
}

} // namespace telemetry::ui
