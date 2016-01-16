#ifndef GENERATOR_H
#define GENERATOR_H
#include <QThread>
#include <QTime>
#include "SignalParams.h"

// Legacy code for packet generation
#include "SVPacket.h"
#include <QElapsedTimer>

class Generator : public QThread {
    Q_OBJECT

public:
    Generator(bool* const stop, const SignalParams& signalParams);
    void setSignalParams(const SignalParams& signalParams);
    void run();
private:
    SignalParams signalParams;
    bool* stop;

    int delayTime;
    void updateDelayTime(int& frameCounter);
    QElapsedTimer frameTimer; // Timer used in frame delay update routine

    EthernetHeader ethernetHeader; // define once for whole generation
    SVPacket generatePacket(int& counter, int& counterForGeneration) const;
signals:
    void setGeneratorIsRunning(bool);
};

#endif // GENERATOR_H
