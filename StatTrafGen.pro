#-------------------------------------------------
#
# Project created by QtCreator 2016-01-13T14:04:14
#
#-------------------------------------------------

QT       += core gui
linux: QMAKE_CXXFLAGS += -std=gnu++0x

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets network

TARGET = StatTrafGen
TEMPLATE = app

win32: INCLUDEPATH += WinPCap/Include

SOURCES += main.cpp\
        MainWindow.cpp \
    Generator.cpp \
    SignalParams.cpp \
    TLV.cpp \
    EthernetHeader.cpp \
    SVPacket.cpp

HEADERS  += MainWindow.h \
    Generator.h \
    SignalParams.h \
    TLV.h \
    EthernetHeader.h \
    SVPacket.h

FORMS    += MainWindow.ui

win32: LIBS += -L../StatTrafGen/WinPCap/Lib -lwpcap
linux: LIBS += -lpcap
