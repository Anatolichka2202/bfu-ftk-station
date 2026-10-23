#include "gui/main_window.h"

#include "protocol/source_registry.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QFrame>
#include <QHeaderView>
#include <QHash>
#include <QLabel>
#include <QLineEdit>
#include <QItemSelectionModel>
#include <QPlainTextEdit>
#include <QTabWidget>
#include <QFontDatabase>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QStyle>
#include <QStringList>
#include <QTableView>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>

#include <string_view>
#include <utility>

namespace telemetry::ui {
namespace {

class TelemetryFilterProxy final : public QSortFilterProxyModel {
public:
    explicit TelemetryFilterProxy(QObject* parent = nullptr)
        : QSortFilterProxyModel(parent) {}

    void setSourceToken(QString token) {
        sourceToken_ = std::move(token);
        invalidateFilter();
    }

    void setSearchText(QString text) {
        searchText_ = std::move(text).trimmed();
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int sourceRow,
                          const QModelIndex& sourceParent) const override {
        const auto sourceIndex =
            sourceModel()->index(sourceRow, TelemetryTableModel::Source,
                                 sourceParent);
        const auto source = sourceIndex.data(Qt::DisplayRole).toString();

        bool sourceAccepted = true;
        if (sourceToken_.startsWith(QStringLiteral("prefix:"))) {
            sourceAccepted =
                source.startsWith(sourceToken_.mid(7), Qt::CaseInsensitive);
        } else if (sourceToken_.startsWith(QStringLiteral("contains:"))) {
            sourceAccepted =
                source.contains(sourceToken_.mid(9), Qt::CaseInsensitive);
        } else if (sourceToken_.startsWith(QStringLiteral("exact:"))) {
            sourceAccepted =
                source.compare(sourceToken_.mid(6), Qt::CaseInsensitive) == 0;
        }

        if (!sourceAccepted) return false;
        if (searchText_.isEmpty()) return true;

        for (int column = 0;
             column < TelemetryTableModel::ColumnCount;
             ++column) {
            const auto text =
                sourceModel()->index(sourceRow, column, sourceParent)
                    .data(Qt::DisplayRole)
                    .toString();
            if (text.contains(searchText_, Qt::CaseInsensitive))
                return true;
        }
        return false;
    }

private:
    QString sourceToken_{QStringLiteral("all")};
    QString searchText_;
};

// This filter changes only what is displayed, never which frames Npcap
// captures or which packets are retained in the journal input queue.
class PacketFilterProxy final : public QSortFilterProxyModel {
public:
    explicit PacketFilterProxy(QObject* parent = nullptr)
        : QSortFilterProxyModel(parent) {}

    void setSourceToken(QString token) {
        sourceToken_ = std::move(token);
        invalidateFilter();
    }

    void setSearchText(QString value) {
        search_ = std::move(value).trimmed();
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override {
        const auto first = sourceModel()->index(row, 0, parent);
        const auto src = first.data(PacketJournalModel::SourceKeyRole).toString();
        const auto dst = first.data(PacketJournalModel::DestinationKeyRole).toString();

        bool accepted = sourceToken_ == QStringLiteral("all");
        if (sourceToken_.startsWith(QStringLiteral("prefix:"))) {
            const auto pattern = sourceToken_.mid(7);
            accepted = src.startsWith(pattern, Qt::CaseInsensitive) ||
                       dst.startsWith(pattern, Qt::CaseInsensitive);
        } else if (sourceToken_.startsWith(QStringLiteral("exact:"))) {
            const auto pattern = sourceToken_.mid(6);
            accepted = src.compare(pattern, Qt::CaseInsensitive) == 0 ||
                       dst.compare(pattern, Qt::CaseInsensitive) == 0;
        }
        if (!accepted) return false;
        if (search_.isEmpty()) return true;

        for (int column = 0; column < PacketJournalModel::ColumnCount; ++column) {
            if (sourceModel()->index(row, column, parent)
                    .data(Qt::DisplayRole).toString()
                    .contains(search_, Qt::CaseInsensitive)) return true;
        }
        // Full MAC addresses remain searchable even when resolved to a name.
        const auto tip = first.data(Qt::ToolTipRole).toString();
        return tip.contains(search_, Qt::CaseInsensitive);
    }

private:
    QString sourceToken_{QStringLiteral("all")};
    QString search_;
};

QFrame* makeMetricCard(QWidget* parent,
                       const QString& title,
                       QLabel*& value) {
    auto* card = new QFrame(parent);
    card->setObjectName(QStringLiteral("metricCard"));

    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(14, 10, 14, 10);
    layout->setSpacing(2);

    auto* caption = new QLabel(title, card);
    caption->setObjectName(QStringLiteral("metricCaption"));

    value = new QLabel(QStringLiteral("0"), card);
    value->setObjectName(QStringLiteral("metricValue"));

    layout->addWidget(caption);
    layout->addWidget(value);
    return card;
}

QString displaySourceName(std::string_view name) {
    auto text =
        QString::fromUtf8(name.data(), static_cast<int>(name.size()));
    return text.replace(QLatin1Char('.'), QStringLiteral(" / "));
}

} // namespace

MainWindow::MainWindow(CaptureService& capture,
                       simulation::SimulationService& simulation,
                       DecoderService& decoder,
                       TelemetryTableModel& model,
                       PacketJournalModel& journal,
                       QWidget* parent)
    : QMainWindow(parent),
      capture_(capture),
      simulation_(simulation),
      decoder_(decoder),
      model_(model),
      journal_(journal) {
    setWindowTitle(QStringLiteral("БСУ ФТК (имитатор) — Ethernet-сниффер"));
    resize(1440, 900);
    setMinimumSize(1100, 700);

    auto* central = new QWidget(this);
    central->setObjectName(QStringLiteral("centralRoot"));

    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(16, 16, 16, 14);
    root->setSpacing(12);

    auto* titleBar = new QFrame(central);
    titleBar->setObjectName(QStringLiteral("topBar"));

    auto* titleLayout = new QHBoxLayout(titleBar);
    titleLayout->setContentsMargins(16, 12, 16, 12);

    auto* titleBlock = new QVBoxLayout;
    titleBlock->setSpacing(0);

    auto* title = new QLabel(QStringLiteral("БСУ ФТК (имитатор)"), titleBar);
    title->setObjectName(QStringLiteral("screenTitle"));

    auto* subtitle = new QLabel(
        QStringLiteral(
            "Имитатор · пассивное наблюдение Ethernet-обмена"),
        titleBar);
    subtitle->setObjectName(QStringLiteral("screenSubtitle"));

    titleBlock->addWidget(title);
    titleBlock->addWidget(subtitle);

    titleLayout->addLayout(titleBlock);
    titleLayout->addStretch();

    captureState_ = new QLabel(titleBar);
    captureState_->setObjectName(QStringLiteral("captureState"));
    captureState_->setAlignment(Qt::AlignCenter);
    captureState_->setMinimumWidth(150);
    titleLayout->addWidget(captureState_);

    root->addWidget(titleBar);

    auto* controlsPanel = new QFrame(central);
    controlsPanel->setObjectName(QStringLiteral("panel"));

    auto* controls = new QHBoxLayout(controlsPanel);
    controls->setContentsMargins(14, 10, 14, 10);
    controls->setSpacing(8);

    auto* modeCaption =
        new QLabel(QStringLiteral("Источник"), controlsPanel);
    modeCaption->setObjectName(QStringLiteral("fieldCaption"));

    inputMode_ = new QComboBox(controlsPanel);
    inputMode_->addItem(QStringLiteral("Живая линия (Npcap)"), 0);
    inputMode_->addItem(QStringLiteral("Эмулятор (без сети)"), 1);

    auto* adapterCaption =
        new QLabel(QStringLiteral("Интерфейс"), controlsPanel);
    adapterCaption->setObjectName(QStringLiteral("fieldCaption"));

    devices_ = new QComboBox(controlsPanel);
    devices_->setMinimumWidth(360);

    refreshDevices_ =
        new QPushButton(QStringLiteral("Обновить"), controlsPanel);
    refreshDevices_->setObjectName(QStringLiteral("secondaryButton"));

    start_ =
        new QPushButton(QStringLiteral("Запустить"), controlsPanel);
    start_->setObjectName(QStringLiteral("primaryButton"));

    stop_ =
        new QPushButton(QStringLiteral("Остановить"), controlsPanel);
    stop_->setObjectName(QStringLiteral("dangerButton"));
    stop_->setEnabled(false);

    controls->addWidget(modeCaption);
    controls->addWidget(inputMode_);
    controls->addSpacing(8);
    controls->addWidget(adapterCaption);
    controls->addWidget(devices_, 1);
    controls->addWidget(refreshDevices_);
    controls->addSpacing(8);
    controls->addWidget(start_);
    controls->addWidget(stop_);

    root->addWidget(controlsPanel);

    auto* metrics = new QHBoxLayout;
    metrics->setSpacing(10);

    metrics->addWidget(makeMetricCard(
        central, QStringLiteral("Принято кадров"), rxValue_));
    metrics->addWidget(makeMetricCard(
        central, QStringLiteral("Потери"), dropValue_));
    metrics->addWidget(makeMetricCard(
        central, QStringLiteral("Декодировано"), decodedValue_));
    metrics->addWidget(makeMetricCard(
        central, QStringLiteral("Ошибки"), errorValue_));
    metrics->addWidget(makeMetricCard(
        central, QStringLiteral("Последняя активность"),
        activityValue_));

    root->addLayout(metrics);

    auto* splitter = new QSplitter(Qt::Horizontal, central);
    splitter->setChildrenCollapsible(false);

    auto* sourcePanel = new QFrame;
    sourcePanel->setObjectName(QStringLiteral("panel"));

    auto* sourceLayout = new QVBoxLayout(sourcePanel);
    sourceLayout->setContentsMargins(10, 12, 10, 10);

    auto* sourceTitle =
        new QLabel(QStringLiteral("ИСТОЧНИКИ"), sourcePanel);
    sourceTitle->setObjectName(QStringLiteral("sectionTitle"));

    sources_ = new QTreeWidget(sourcePanel);
    sources_->setHeaderHidden(true);
    sources_->setRootIsDecorated(true);
    sources_->setUniformRowHeights(true);

    sourceLayout->addWidget(sourceTitle);
    sourceLayout->addWidget(sources_);
    buildSourceTree();

    auto* telemetryPanel = new QFrame;
    telemetryPanel->setObjectName(QStringLiteral("panel"));

    auto* telemetryLayout = new QVBoxLayout(telemetryPanel);
    telemetryLayout->setContentsMargins(10, 12, 10, 10);
    telemetryLayout->setSpacing(8);

    auto* tableHeader = new QHBoxLayout;

    auto* tableTitle =
        new QLabel(QStringLiteral("ТЕЛЕМЕТРИЯ"), telemetryPanel);
    tableTitle->setObjectName(QStringLiteral("sectionTitle"));

    filter_ = new QLineEdit(telemetryPanel);
    filter_->setClearButtonEnabled(true);
    filter_->setPlaceholderText(
        QStringLiteral(
            "Поиск по источнику, устройству или параметру"));
    filter_->setMaximumWidth(430);

    tableHeader->addWidget(tableTitle);
    tableHeader->addStretch();
    tableHeader->addWidget(filter_);

    telemetryLayout->addLayout(tableHeader);

    proxy_ = new TelemetryFilterProxy(this);
    proxy_->setSourceModel(&model_);
    proxy_->setDynamicSortFilter(true);

    table_ = new QTableView(telemetryPanel);
    table_->setModel(proxy_);
    table_->setSortingEnabled(true);
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setVisible(false);

    table_->horizontalHeader()->setSectionResizeMode(
        TelemetryTableModel::Source,
        QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(
        TelemetryTableModel::Device,
        QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(
        TelemetryTableModel::Parameter,
        QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(
        TelemetryTableModel::RawValue,
        QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(
        TelemetryTableModel::AgeMs,
        QHeaderView::ResizeToContents);

    table_->sortByColumn(
        TelemetryTableModel::Source, Qt::AscendingOrder);

    telemetryLayout->addWidget(table_);

    splitter->addWidget(sourcePanel);
    splitter->addWidget(telemetryPanel);
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({250, 1050});

    root->addWidget(splitter, 1);

    diagnostics_ =
        new QLabel(QStringLiteral("Готово к запуску"), central);
    diagnostics_->setObjectName(QStringLiteral("diagnostics"));
    diagnostics_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    root->addWidget(diagnostics_);

    setCentralWidget(central);

    connect(inputMode_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::updateInputMode);
    connect(refreshDevices_, &QPushButton::clicked,
            this, &MainWindow::refreshDevices);
    connect(start_, &QPushButton::clicked,
            this, &MainWindow::startCapture);
    connect(stop_, &QPushButton::clicked,
            this, &MainWindow::stopCapture);

    connect(filter_, &QLineEdit::textChanged,
            this, [this](const QString& text) {
                static_cast<TelemetryFilterProxy*>(proxy_)
                    ->setSearchText(text);
            });

    connect(sources_, &QTreeWidget::currentItemChanged,
            this, [this] { applySourceFilter(); });

    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(33);
    connect(drainTimer_, &QTimer::timeout,
            &model_, &TelemetryTableModel::drain);
    connect(drainTimer_, &QTimer::timeout,
            &journal_, &PacketJournalModel::drain);
    drainTimer_->start();

    statusTimer_ = new QTimer(this);
    statusTimer_->setInterval(250);
    connect(statusTimer_, &QTimer::timeout,
            this, &MainWindow::updateStatus);
    statusTimer_->start();

    setStyleSheet(QStringLiteral(R"(
        QMainWindow, QWidget#centralRoot {
            background: #10171f;
            color: #dce6ef;
        }

        QFrame#topBar,
        QFrame#panel,
        QFrame#metricCard {
            background: #17212b;
            border: 1px solid #2a3946;
            border-radius: 6px;
        }

        QLabel#screenTitle {
            font-size: 22px;
            font-weight: 700;
            color: #f3f7fa;
        }

        QLabel#screenSubtitle {
            font-size: 12px;
            color: #8fa2b3;
        }

        QLabel#sectionTitle,
        QLabel#fieldCaption,
        QLabel#metricCaption {
            color: #90a4b5;
            font-size: 11px;
            font-weight: 600;
        }

        QLabel#metricValue {
            color: #eef4f8;
            font-size: 20px;
            font-weight: 700;
        }

        QLabel#captureState {
            padding: 7px 12px;
            border-radius: 4px;
            font-weight: 700;
        }

        QLabel#captureState[state="idle"] {
            background: #26323d;
            color: #aebdca;
        }

        QLabel#captureState[state="running"] {
            background: #143b32;
            color: #67d7b0;
            border: 1px solid #2b735e;
        }

        QLabel#captureState[state="warning"] {
            background: #44371d;
            color: #f2c76e;
            border: 1px solid #7d6328;
        }

        QLabel#captureState[state="error"] {
            background: #48272b;
            color: #ff9199;
            border: 1px solid #8a3f48;
        }

        QComboBox,
        QLineEdit {
            background: #0f171e;
            color: #e1e9ef;
            border: 1px solid #344554;
            border-radius: 4px;
            padding: 6px 8px;
            min-height: 22px;
        }

        QComboBox:focus,
        QLineEdit:focus {
            border: 1px solid #4b91d1;
        }

        QPushButton {
            background: #263643;
            color: #dfe8ee;
            border: 1px solid #3b4d5b;
            border-radius: 4px;
            padding: 7px 14px;
            font-weight: 600;
        }

        QPushButton:hover {
            background: #304454;
        }

        QPushButton:disabled {
            color: #637482;
            background: #1a252e;
            border-color: #293641;
        }

        QPushButton#primaryButton {
            background: #1d5f91;
            border-color: #2e7fba;
            color: white;
        }

        QPushButton#primaryButton:hover {
            background: #246fa7;
        }

        QPushButton#dangerButton {
            background: #603038;
            border-color: #87434e;
        }

        QTreeWidget,
        QTableView {
            background: #111a22;
            alternate-background-color: #15202a;
            color: #dce6ef;
            border: 1px solid #283744;
            gridline-color: #263540;
            selection-background-color: #244d6c;
            selection-color: #ffffff;
        }

        QTreeWidget::item {
            padding: 5px 4px;
        }

        QHeaderView::section {
            background: #1b2833;
            color: #9fb1c0;
            border: 0;
            border-right: 1px solid #2c3a46;
            border-bottom: 1px solid #334451;
            padding: 7px 8px;
            font-weight: 600;
        }

        QLabel#diagnostics {
            color: #728798;
            font-family: monospace;
            padding: 2px 4px;
        }

        QSplitter::handle {
            background: #10171f;
            width: 8px;
        }
    )"));

    setCaptureState(QStringLiteral("ОСТАНОВЛЕНО"), "idle");
    refreshDevices();
    updateInputMode();
}

void MainWindow::buildSourceTree() {
    sources_->clear();

    auto* all = new QTreeWidgetItem(
        sources_, {QStringLiteral("Все абоненты")});
    all->setData(0, Qt::UserRole, QStringLiteral("all"));

    QHash<QString, QTreeWidgetItem*> stages;

    const auto stageToken = [](std::string_view stage) {
        if (stage == "СТУПЕНЬ Б") return QStringLiteral("prefix:B.");
        if (stage == "СТУПЕНЬ А") return QStringLiteral("prefix:A.");
        if (stage == "НАЗЕМКА") return QStringLiteral("prefix:GROUND.");
        if (stage == "РЕЗЕРВ") return QStringLiteral("prefix:RESERVE.");
        return QStringLiteral("all");
    };

    const auto ipv4Text = [](std::uint32_t value) {
        return QStringLiteral("%1.%2.%3.%4")
            .arg((value >> 24) & 0xFFU)
            .arg((value >> 16) & 0xFFU)
            .arg((value >> 8) & 0xFFU)
            .arg(value & 0xFFU);
    };

    const auto macText = [](const protocol::MacAddress& mac) {
        QStringList parts;
        for (const auto byte : mac) {
            parts << QStringLiteral("%1")
                         .arg(byte, 2, 16, QLatin1Char('0'))
                         .toUpper();
        }
        return parts.join(QLatin1Char(':'));
    };

    for (const auto& source : protocol::knownSources()) {
        if (source.block == "БСУ:ФТК") continue; // Наши адреса, не внешний абонент.
        const auto stageName = QString::fromUtf8(
            source.stage.data(), static_cast<int>(source.stage.size()));

        auto* stageItem = stages.value(stageName, nullptr);
        if (!stageItem) {
            stageItem = new QTreeWidgetItem(sources_, {stageName});
            stageItem->setData(0, Qt::UserRole, stageToken(source.stage));
            stages.insert(stageName, stageItem);
        }

        const auto block = QString::fromUtf8(
            source.block.data(), static_cast<int>(source.block.size()));
        const auto cell = QString::fromUtf8(
            source.cell.data(), static_cast<int>(source.cell.size()));

        QString label = block + QStringLiteral(" / ") + cell;
        if (!source.reserved && source.ipv4 != 0U) {
            label += QStringLiteral(" — %1:%2")
                         .arg(ipv4Text(source.ipv4))
                         .arg(source.port);
        }

        auto* item = new QTreeWidgetItem(stageItem, {label});
        item->setData(
            0,
            Qt::UserRole,
            QStringLiteral("exact:") +
                QString::fromUtf8(
                    source.name.data(),
                    static_cast<int>(source.name.size())));

        item->setToolTip(
            0,
            QStringLiteral("MAC: %1").arg(macText(source.mac)));
    }

    for (auto it = stages.begin(); it != stages.end(); ++it) {
        it.value()->setExpanded(true);
    }

    sources_->setCurrentItem(all);
}

void MainWindow::refreshDevices() {
    const auto previous = devices_->currentData().toString();
    devices_->clear();

    std::string error;
    const auto devices = CaptureService::availableDevices(error);

    int restoreIndex = -1;
    int index = 0;

    for (const auto& dev : devices) {
        const auto label =
            dev.description.empty()
                ? QStringLiteral("Ethernet-интерфейс %1")
                      .arg(index + 1)
                : QString::fromStdString(dev.description);

        devices_->addItem(
            label, QString::fromStdString(dev.name));

        devices_->setItemData(
            index,
            QString::fromStdString(dev.name),
            Qt::ToolTipRole);

        if (QString::fromStdString(dev.name) == previous)
            restoreIndex = index;

        ++index;
    }

    if (restoreIndex >= 0)
        devices_->setCurrentIndex(restoreIndex);

    if (devices.empty()) {
        diagnostics_->setText(
            error.empty()
                ? QStringLiteral("Npcap-интерфейсы не найдены")
                : QString::fromStdString(error));
    }
}

void MainWindow::startCapture() {
    std::string error;

    if (simulationMode()) {
        simulation_.start();
    } else {
        if (devices_->currentIndex() < 0) return;
        const auto device =
            devices_->currentData().toString().toStdString();
        const auto bpf = protocol::buildCaptureFilter();

        if (!capture_.start(device, bpf, error)) {
            setCaptureState(QStringLiteral("ОШИБКА"), "error");
            diagnostics_->setText(QString::fromStdString(error));
            return;
        }
    }

    lastCaptured_ = 0;
    activitySeen_ = false;

    inputMode_->setEnabled(false);
    devices_->setEnabled(false);
    refreshDevices_->setEnabled(false);
    start_->setEnabled(false);
    stop_->setEnabled(true);

    setCaptureState(
        QStringLiteral("ОЖИДАНИЕ ДАННЫХ"), "warning");
}

void MainWindow::stopCapture() {
    capture_.stop();
    simulation_.stop();

    inputMode_->setEnabled(true);
    start_->setEnabled(true);
    stop_->setEnabled(false);
    updateInputMode();

    setCaptureState(QStringLiteral("ОСТАНОВЛЕНО"), "idle");
}

void MainWindow::applySourceFilter() {
    const auto* item = sources_->currentItem();
    const auto token =
        item
            ? item->data(0, Qt::UserRole).toString()
            : QStringLiteral("all");

    static_cast<TelemetryFilterProxy*>(proxy_)
        ->setSourceToken(token);
}

void MainWindow::setCaptureState(const QString& text,
                                 const char* state) {
    captureState_->setText(text);
    captureState_->setProperty(
        "state", QString::fromLatin1(state));

    captureState_->style()->unpolish(captureState_);
    captureState_->style()->polish(captureState_);
}

void MainWindow::updateStatus() {
    const auto cs = capture_.stats();
    const auto ss = simulation_.stats();
    const auto ds = decoder_.stats();

    const bool simulated = simulationMode() || simulation_.running();
    const auto received = simulated ? ss.generated : cs.captured;
    const auto inputDrops = simulated
        ? ss.queueDrops
        : (cs.queueDrops + cs.pcapDropped + cs.pcapInterfaceDropped);

    if (received != lastCaptured_) {
        lastCaptured_ = received;
        if (!activitySeen_) {
            activitySeen_ = true;
            activityTimer_.start();
        } else {
            activityTimer_.restart();
        }
    }

    const auto totalDrops = inputDrops + ds.batchDrops + ds.journalDrops;
    const auto totalErrors = ds.decodeErrors;

    rxValue_->setText(QString::number(received));
    dropValue_->setText(QString::number(totalDrops));
    decodedValue_->setText(QString::number(ds.packetsDecoded));
    errorValue_->setText(QString::number(totalErrors));
    activityValue_->setText(
        activitySeen_
            ? QStringLiteral("%1 мс").arg(activityTimer_.elapsed())
            : QStringLiteral("—"));

    const auto error = simulated ? std::string{} : capture_.lastError();
    const bool running = simulated ? simulation_.running() : capture_.running();

    if (running) {
        setCaptureState(
            activitySeen_ && activityTimer_.elapsed() < 1200
                ? (simulated ? QStringLiteral("ЭМУЛЯЦИЯ") : QStringLiteral("ПРИЁМ"))
                : QStringLiteral("НЕТ КАДРОВ"),
            activitySeen_ && activityTimer_.elapsed() < 1200
                ? "running" : "warning");
    } else if (!error.empty()) {
        setCaptureState(QStringLiteral("ОШИБКА"), "error");
        if (stop_->isEnabled()) {
            stop_->setEnabled(false);
            start_->setEnabled(true);
            inputMode_->setEnabled(true);
            updateInputMode();
        }
    } else if (stop_->isEnabled()) {
        stop_->setEnabled(false);
        start_->setEnabled(true);
        inputMode_->setEnabled(true);
        updateInputMode();
        setCaptureState(QStringLiteral("ОСТАНОВЛЕНО"), "idle");
    }

    diagnostics_->setText(
        simulated
            ? QStringLiteral(
                  "mode=simulation  queue_drop=%1  decode_error=%2  "
                  "ignored=%3  batch_drop=%4")
                  .arg(ss.queueDrops)
                  .arg(ds.decodeErrors)
                  .arg(ds.packetsIgnored)
                  .arg(ds.batchDrops)
            : QStringLiteral(
                  "mode=npcap  capture_queue_drop=%1  pcap_drop=%2  "
                  "if_drop=%3  decode_error=%4  ignored=%5  batch_drop=%6%7")
                  .arg(cs.queueDrops)
                  .arg(cs.pcapDropped)
                  .arg(cs.pcapInterfaceDropped)
                  .arg(ds.decodeErrors)
                  .arg(ds.packetsIgnored)
                  .arg(ds.batchDrops)
                  .arg(error.empty()
                           ? QString{}
                           : QStringLiteral("  |  ") +
                                 QString::fromStdString(error)));
}

bool MainWindow::simulationMode() const {
    return inputMode_ && inputMode_->currentData().toInt() == 1;
}

void MainWindow::updateInputMode() {
    const bool live = !simulationMode();
    devices_->setEnabled(live && !capture_.running() && !simulation_.running());
    refreshDevices_->setEnabled(live && !capture_.running() && !simulation_.running());
}


} // namespace telemetry::ui
