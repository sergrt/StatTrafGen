#include "Generator.h"
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
#undef min
#undef max

#include <QNetworkInterface>
#include <vector>
#define _USE_MATH_DEFINES
#include <math.h>
#include <limits>
using namespace std;
//#include <thread>
void uDelay(int val) {
    if (val > 1000 * 1000 || val == 0)
        return;
    //// This does not work under windows - sleeping too long
    //std::this_thread::sleep_for(std::chrono::microseconds(val));
    //return;

    #ifdef WIN32
        LARGE_INTEGER li;
        QueryPerformanceFrequency(&li);
        const double PCFreq = double(li.QuadPart)/1000000.0;
        QueryPerformanceCounter(&li);
        __int64 CounterStart = li.QuadPart;
        while (true) {
            QueryPerformanceCounter(&li);
            const double sleep = double(li.QuadPart-CounterStart)/PCFreq;
            if (sleep > val)
                break;
        }
    #else
        timespec a;
        clock_gettime(CLOCK_REALTIME, &a);
        ldiv_t t = ldiv(a.tv_nsec + val*1000, 1000000000l);
        timespec ts;
        ts.tv_sec = a.tv_sec + t.quot;
        ts.tv_nsec = t.rem;
        clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
    #endif
}

void rmemcpy(unsigned char* dst, const unsigned char* const src, const unsigned int count) {
    for (unsigned int i = 0; i < count; ++i)
        dst[count - 1 - i] = src[i];
}

Generator::Generator(bool* const stop, const SignalParams& signalParams)
    : stop {stop}, signalParams {signalParams}, ethernetHeader {signalParams.dstMac, signalParams.srcMac} {
    setSignalParams(signalParams);

}
void Generator::setSignalParams(const SignalParams& signalParams) {
    this->signalParams = signalParams;
    ethernetHeader = EthernetHeader(signalParams.dstMac, signalParams.srcMac);
}

void Generator::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_findalldevs(&alldevs, errbuf);
    pcap_if_t* d = alldevs;

    QString mac;
    for (int i = 0; i < sizeof(signalParams.srcMac); i++)
        mac += QString("%1:").arg(signalParams.srcMac[i], 2, 16, QChar('0')).toUpper();
    mac.remove(mac.length() - 1, 1);

    QList<QNetworkInterface> ifs = QNetworkInterface::allInterfaces();
    int ifsID = 0;
    while (ifsID < ifs.count()) {
        qDebug(ifs.at(ifsID).hardwareAddress().toLocal8Bit());
        qDebug(mac.toLocal8Bit());

        if (ifs.at(ifsID).hardwareAddress() == mac)
            break;
        ++ifsID;
    }

    const QString ifName = ifs.at(ifsID).name();
    QString curID = QString(d->name);
    curID = curID.right(curID.length() - curID.indexOf('{'));
    while (ifName != curID) {
        d = d->next;
        curID = QString(d->name);
        curID = curID.right(curID.length() - curID.indexOf('{'));
    }

    pcap_t* fp= pcap_open_live(d->name, // name of the device
        4096,                           // portion of the packet to capture
        1,                              // promiscuous mode
        1000,                           // read timeout
        errbuf                          // error buffer
        );

    emit setGeneratorIsRunning(true);

    int svCnt = 0; // SV counter
    int counterForGeneration = 0; // Used in generator to seamless signal generation
    int totalTransmitted = 0; // Total transmitted packets

    QElapsedTimer controlTimer; // Timer for rate control
    controlTimer.start();
    int controlFrameCounter = 0;

    delayTime = 500; // initial delay time, microseconds
    frameTimer.start();
    int frameCounter = 0; // count of transmitted frames, used in time correction

    const int FRAME_CNT_UPDATE_TIMER = 500; // How often update sleep interval
    while(!*stop) {
        SVPacket p = generatePacket(svCnt, counterForGeneration);
        vector<unsigned char> tmp;
        p.getPacket(tmp);

        if (pcap_sendpacket(fp, tmp.data(), tmp.size()) == 0) {
            ++totalTransmitted;
            ++frameCounter;
            ++controlFrameCounter;
        } else {
            qDebug() << "Error transmitting! " << pcap_geterr(fp);
        }

        if (svCnt == 0) {
            qDebug() << "Frame counter" << controlFrameCounter << "in " << controlTimer.restart() << "total_transmitted = " << totalTransmitted;
            controlFrameCounter = 0;
        }

        if (frameCounter >= FRAME_CNT_UPDATE_TIMER)
            updateDelayTime(frameCounter);

        uDelay(delayTime);
    }
    pcap_close(fp);
    emit setGeneratorIsRunning(false);

    qDebug() << "Total frames send" << totalTransmitted;
}

void Generator::updateDelayTime(int& frameCounter) {
    const double elapsed = frameTimer.nsecsElapsed() / 1000.0;

    // Rates per microsecond
    const double desiredRate = 1.0e-6 * signalParams.getFramesPerPeriod() * 50.0 /*50 Hz*/ / static_cast<double>(signalParams.getValsPerPacket());
    const double actualRate = static_cast<double>(frameCounter) / elapsed;
    const double delayAdd = 1.0 / desiredRate - 1.0 / actualRate;
    //qDebug() << "desiredRate = " << desiredRate << ", actualRate = " << actualRate << ", elapsed = " << elapsed
    //         << ", delayAdd = " << delayAdd;
    if (delayAdd != std::numeric_limits<double>::max()) {
        delayTime += round(delayAdd);// - 2*frameTimer.nsecsElapsed() / 1000.0;//1.2 * 10;
        if (delayTime < 0)
            delayTime = 0;
    }

    //qDebug() << "Delay time set to" << delayTime;
    frameTimer.restart();
    frameCounter = 0;
}

SVPacket Generator::generatePacket(int& counter, int& counterForGeneration) const {
    //////////////////////////////////////////////////////////////////////////
    // Create savPDU TLV

    vector<unsigned char> tmp;

    //////////////////////////////////////////////////////////////////////////
    // noASDU
    // const unsigned char asdu_count = 0x08; // Number of groups in one packet - 1 for 80 points, 8 for 256

    const unsigned char asdu_count = signalParams.getValsPerPacket();//(genParams.discrete == 80 ? 0x01 : 0x08); // Число групп в одном пакете - 1 для 80 точек, 8 для 256

    tmp.push_back(asdu_count);
    TLV noASDU(0x80, tmp);

    //////////////////////////////////////////////////////////////////////////
    // sequence of ASDU

    vector<unsigned char> sequenceASDU_data;
    for (int i = 0; i < asdu_count; i++) {
        //////////////////////////////////////////////////////////////////////////
        // svID
        TLV svID(0x80, signalParams.svId);

        //////////////////////////////////////////////////////////////////////////
        // smpCnt
        tmp.clear();
        tmp.push_back(static_cast<unsigned char>(counter >> 8));
        tmp.push_back(static_cast<unsigned char>(counter));
        TLV smpCnt(0x82, tmp);

        //////////////////////////////////////////////////////////////////////////
        //confRev - configuration version. Fixed = 1 for LE specification
        tmp.clear();
        char confRev_raw[4] = {0x00, 0x00, 0x00, 0x01};
        tmp.resize(4);
        memcpy(tmp.data(), &confRev_raw, 4);
        TLV confRev(0x83, tmp);

        //////////////////////////////////////////////////////////////////////////
        //smpSync - flag, identifying if there is external time sync
        tmp.clear();
        //if (counter == 1)
            tmp.push_back(0x01);
        //else
            //tmp.push_back( 0x00 );
        TLV smpSync(0x85, tmp);

        //////////////////////////////////////////////////////////////////////////
        // Sequence of data
        tmp.clear();

        //double pt_count = 50 * (signalParams.getFramesPerPeriod()) / signalParams.freq;
        double val_Ua;
        double val_Ub;
        double val_Uc;
        double val_Un;

        //val_Ua = genParams.Ua_A * 100.0 * qSin(genParams.Ua_G + (counter  - (int)(counter / pt_count) * pt_count) * (2 * 3.14) / pt_count);

        {
            double a1 = 2*M_PI*signalParams.freq/(signalParams.getFramesPerPeriod()*50.0);
            double a2 = M_PI/180.0;
            double alpha = a1;
            double beta = signalParams.Ua_Phase*a2;
            double Ucommon_a = 1.0*sin(alpha*counterForGeneration + beta);
            val_Ua = Ucommon_a * signalParams.Ua_Amplitude * 100.0;

            double Ucommon_b = 1.0*sin(alpha*counterForGeneration + beta);
            val_Ub = Ucommon_b * signalParams.Ub_Amplitude * 100.0;

            double Ucommon_c = 1.0*sin(alpha*counterForGeneration + beta);
            val_Uc = Ucommon_c * signalParams.Uc_Amplitude * 100.0;

            double Ucommon_n = 1.0*sin(alpha*counterForGeneration + beta);
            val_Un = Ucommon_n * signalParams.Un_Amplitude * 100.0;
        }

        double val_Ia;
        double val_Ib;
        double val_Ic;
        double val_In;
        {
            double a1 = 2*M_PI*signalParams.freq/(signalParams.getFramesPerPeriod()*50.0);
            double a2 = M_PI/180.0;
            double alpha = a1;
            double beta = signalParams.Ia_Phase*a2;
            double Icommon_a = 1*sin(alpha*counterForGeneration + beta);
            val_Ia = Icommon_a * signalParams.Ia_Amplitude * 1000;

            double Icommon_b = 1*sin(alpha*counterForGeneration + beta);
            val_Ib = Icommon_b * signalParams.Ib_Amplitude * 1000;

            double Icommon_c = 1*sin(alpha*counterForGeneration + beta);
            val_Ic = Icommon_c * signalParams.Ic_Amplitude * 1000;

            double Icommon_n = 1*sin(alpha*counterForGeneration + beta);
            val_In = Icommon_n * signalParams.In_Amplitude * 1000;
        }

        int iValUa = round(val_Ua);//static_cast<int>(val_Ua);
        int iValUb = round(val_Ub);//static_cast<int>(val_Ub);
        int iValUc = round(val_Uc);//static_cast<int>(val_Uc);
        int iValUn = round(val_Un);//static_cast<int>(val_Un);

        int iValIa = round(val_Ia);//static_cast<int>(val_Ia);
        int iValIb = round(val_Ib);//static_cast<int>(val_Ib);
        int iValIc = round(val_Ic);//static_cast<int>(val_Ic);
        int iValIn = round(val_In);//static_cast<int>(val_In);
        const int zero = 0;

        // Ia
        int rs = tmp.size();
        tmp.resize(rs + 8);
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValIa, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // Ib
        rs = tmp.size();
        tmp.resize(rs + 8);
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValIb, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // Ic
        rs = tmp.size();
        tmp.resize( rs + 8 );
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValIc, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // In
        rs = tmp.size();
        tmp.resize( rs + 8 );
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValIn, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // Ua
        rs = tmp.size();
        tmp.resize( rs + 8 );
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValUa, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // Ub
        rs = tmp.size();
        tmp.resize( rs + 8 );
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValUb, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // Uc
        rs = tmp.size();
        tmp.resize( rs + 8 );
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValUc, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        // Un
        rs = tmp.size();
        tmp.resize( rs + 8 );
        rmemcpy(tmp.data() + rs, (const unsigned char * const)&iValUn, 4);
        memcpy(tmp.data() + rs + 4, &zero, 4);

        TLV dataSet(0x87, tmp);

        vector<unsigned char> asdu_data_total;
        svID.getPacket(tmp);
        rs = asdu_data_total.size();
        asdu_data_total.resize(rs + tmp.size());
        memcpy(asdu_data_total.data() + rs, tmp.data(), tmp.size());

        smpCnt.getPacket(tmp);
        rs = asdu_data_total.size();
        asdu_data_total.resize(rs + tmp.size());
        memcpy(asdu_data_total.data() + rs, tmp.data(), tmp.size());

        confRev.getPacket(tmp);
        rs = asdu_data_total.size();
        asdu_data_total.resize(rs + tmp.size());
        memcpy(asdu_data_total.data() + rs, tmp.data(), tmp.size());

        smpSync.getPacket(tmp);
        rs = asdu_data_total.size();
        asdu_data_total.resize(rs + tmp.size());
        memcpy(asdu_data_total.data() + rs, tmp.data(), tmp.size());

        dataSet.getPacket(tmp);
        rs = asdu_data_total.size();
        asdu_data_total.resize(rs + tmp.size());
        memcpy(asdu_data_total.data() + rs, tmp.data(), tmp.size());

        TLV ASDU(0x30, asdu_data_total);
        ASDU.getPacket(tmp);
        rs = sequenceASDU_data.size();
        sequenceASDU_data.resize(rs + tmp.size());
        memcpy(sequenceASDU_data.data() + rs, tmp.data(), tmp.size());

        ++counter;
        ++counterForGeneration;
        if (counter >= signalParams.getFramesPerPeriod() * 50) // на промышленной частоте
            counter = 0;
    }

    TLV sequenceASDU(0xA2, sequenceASDU_data);

    vector<unsigned char> savPDU_tmp;
    sequenceASDU.getPacket(savPDU_tmp);
    noASDU.getPacket(tmp);
    int rs = tmp.size();
    tmp.resize(rs + savPDU_tmp.size());
    memcpy(tmp.data() + rs, savPDU_tmp.data(), savPDU_tmp.size());

    vector<unsigned char>& savPDU_data = tmp;

    TLV savPDU(0x60, savPDU_data);

    // APPID set as default
    unsigned char APPID[2];
    APPID[0] = 0x40;
    APPID[1] = 0x00;

    SVPacket p(ethernetHeader, APPID, savPDU);
    return p;
}

