#include "SignalParams.h"

SignalParams::SignalParams() {
    // Init with something
    Ua_Amplitude =
            Ub_Amplitude =
            Uc_Amplitude =
            Un_Amplitude = 0.0;
    Ua_Phase =
            Ub_Phase =
            Uc_Phase =
            Un_Phase = 0.0;
    Ia_Amplitude =
            Ib_Amplitude =
            Ic_Amplitude =
            In_Amplitude = 0.0;
    Ia_Phase =
            Ib_Phase =
            Ic_Phase =
            In_Phase = 0.0;

    sampleRate = SV_SAMPLE_RATE::SV_SAMPLE_RATE_80;

    dstMac[0] = 0x00;
    dstMac[1] = 0x25;
    dstMac[2] = 0x22;
    dstMac[3] = 0xEB;
    dstMac[4] = 0xC5;
    dstMac[5] = 0x51;

    srcMac[0] = 0x00;
    srcMac[1] = 0x25;
    srcMac[2] = 0x22;
    srcMac[3] = 0xEB;
    srcMac[4] = 0xC5;
    srcMac[5] = 0x51;

    svId.push_back('S');
    svId.push_back('V');
    svId.push_back('0');
    svId.push_back('0');
    svId.push_back('1');
}

void SignalParams::setSrcMac(const QString& mac) {
    for (int i = 0; i < 6; ++i)
        srcMac[i] = mac.mid(i*3,2).toInt(0,16);
}

unsigned int SignalParams::getFramesPerPeriod() const {
    unsigned int res;
    switch(sampleRate) {
    case SV_SAMPLE_RATE::SV_SAMPLE_RATE_80:
        res = 80;
        break;
    case SV_SAMPLE_RATE::SV_SAMPLE_RATE_256:
        res = 256;
        break;
    default:
        res = 80;
        break;
    }
    return res;
}

unsigned int SignalParams::getValsPerPacket() const {
    unsigned int res;
    switch(sampleRate) {
    case SV_SAMPLE_RATE::SV_SAMPLE_RATE_80:
        res = 1;
        break;
    case SV_SAMPLE_RATE::SV_SAMPLE_RATE_256:
        res = 8;
        break;
    default:
        res = 1;
        break;
    }
    return res;
}
