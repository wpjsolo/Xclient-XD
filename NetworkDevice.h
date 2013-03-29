#ifndef NETWORKDEVICE_H
#define NETWORKDEVICE_H

#include "pcaphelper.h"
#include "WinSock2.h"
#include "QString"
#include "QList"
#include "QDebug"

#pragma comment(lib,"ws2_32.lib")

struct NetworkDevice
{
    QString name;
    QString description;
};


#endif // NETWORKDEVICE_H
