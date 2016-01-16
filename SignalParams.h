#ifndef SIGNALPARAMS_H
#define SIGNALPARAMS_H
#include <QString>
#include <vector>
using namespace std;

class SignalParams {
public:
    SignalParams();

    enum class SV_SAMPLE_RATE {
        SV_SAMPLE_RATE_80,
        SV_SAMPLE_RATE_256
    };

    double Ua_Amplitude;
    double Ub_Amplitude;
    double Uc_Amplitude;
    double Un_Amplitude;
    double Ua_Phase;
    double Ub_Phase;
    double Uc_Phase;
    double Un_Phase;

    double Ia_Amplitude;
    double Ib_Amplitude;
    double Ic_Amplitude;
    double In_Amplitude;
    double Ia_Phase;
    double Ib_Phase;
    double Ic_Phase;
    double In_Phase;

    double freq;

    SV_SAMPLE_RATE sampleRate;

    unsigned char dstMac[6];
    unsigned char srcMac[6];
    vector<unsigned char> svId;

public:
    void setSrcMac(const QString& mac);
    unsigned int getFramesPerPeriod() const;
    unsigned int getValsPerPacket() const;
};

#endif // SIGNALPARAMS_H
