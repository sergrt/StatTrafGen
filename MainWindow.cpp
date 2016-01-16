#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QNetworkInterface>

const QString MAC_PROPERTY_NAME = "Mac";

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
    connect(ui->bnStartStop, &QPushButton::clicked, this, &MainWindow::onStartStopClicked);

    onSetGeneratorIsRunning(false);

    QList<QNetworkInterface> ifs = QNetworkInterface::allInterfaces();
    for (int i = 0; i < ifs.count(); ++i) {
        if (ifs.at(i).hardwareAddress().length() == 17) { // MAC 6 bytes
            QString ipStr = "---.---.---.---";
            for (int x = 0; x < ifs.at(i).addressEntries().count(); x++) {
                if (ifs.at(i).addressEntries().at(x).ip().protocol() == QAbstractSocket::IPv4Protocol) {
                    ipStr = ifs.at(i).addressEntries().at(x).ip().toString();
                    break;
                }
            }

            QString s = ifs.at(i).hardwareAddress();
            ui->cbNetworkInterface->addItem(s);
            ui->cbNetworkInterface->setProperty(QString(MAC_PROPERTY_NAME + "%1").arg(ui->cbNetworkInterface->count() - 1).toLocal8Bit(), ifs.at(i).hardwareAddress());
        }
    }

    ui->cbNetworkInterface->setCurrentIndex(0);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onStartStopClicked() {
    if (!generator || (generatorStopped && !generator->isRunning())) {
        SignalParams signalParams;
        const QString mac = ui->cbNetworkInterface->property(QString(MAC_PROPERTY_NAME + "%1").arg(ui->cbNetworkInterface->currentIndex()).toLocal8Bit()).toString();
        signalParams.setSrcMac(mac);
        signalParams.sampleRate = ui->rb80->isChecked() ? SignalParams::SV_SAMPLE_RATE::SV_SAMPLE_RATE_80 :
                                             SignalParams::SV_SAMPLE_RATE::SV_SAMPLE_RATE_256;

        if (!generator) {
            generator.reset(new Generator(&generatorStopped, signalParams));
            connect(generator.get(), &Generator::setGeneratorIsRunning, this, &MainWindow::onSetGeneratorIsRunning);
        } else {
            generator->setSignalParams(signalParams);
        }


        generatorStopped = false;

        generator->start();
    } else {
        generatorStopped = true;
    }
}

void MainWindow::onSetGeneratorIsRunning(bool isRunning) {
    ui->bnStartStop->setText(isRunning ? tr("Остановить") : tr("Запустить"));
}
