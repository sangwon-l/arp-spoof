TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
QMAKE_CXXFLAGS += -std=c++0x -pthread
LIBS += -lpcap
LIBS += -pthread

SOURCES += \
        arphdr.cpp \
        ethhdr.cpp \
        ip.cpp \
        mac.cpp \
        main.cpp

HEADERS += \
    arphdr.h \
    ethhdr.h \
    ip.h \
    mac.h
