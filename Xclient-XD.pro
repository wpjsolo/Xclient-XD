#-------------------------------------------------
#
# Project created by QtCreator 2013-03-28T10:57:36
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Xclient-XD
TEMPLATE = app

SOURCES += main.cpp\
        mainwindow.cpp \
    NetworkDevice.cpp

HEADERS  += mainwindow.h \
    NetworkDevice.h \
    pcaphelper.h


INCLUDEPATH += "D:/DevelopEnvironment/WpdPack/Include"

LIBS += -L"D:/DevelopEnvironment/WpdPack/Lib"

FORMS    += mainwindow.ui
