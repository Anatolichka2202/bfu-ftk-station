#include "capture/capture_service.h"
#include "gui/main_window.h"
#include "model/telemetry_table_model.h"
#include "simulation/simulation_service.h"
#include "telemetry/decoder_service.h"

#include <QApplication>

#include <semaphore>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    telemetry::PacketQueue packetQueue;
    telemetry::BatchQueue batchQueue;
    std::counting_semaphore<1024> packetReady{0};

    telemetry::CaptureService capture(packetQueue, packetReady);
    telemetry::DecoderService decoder(packetQueue, packetReady, batchQueue);
    telemetry::simulation::SimulationService simulation(packetQueue, packetReady);
    telemetry::ui::TelemetryTableModel model(batchQueue);

    decoder.start();
    telemetry::ui::MainWindow window(capture, simulation, decoder, model);
    window.show();

    const int rc = app.exec();
    capture.stop();
    simulation.stop();
    decoder.stop();
    return rc;
}
