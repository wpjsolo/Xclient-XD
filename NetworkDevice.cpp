#include "NetworkDevice.h"

bool findDevices(QList<NetworkDevice> *deviceList)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs,*dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug()<<errbuf;
        return false;
    }
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        NetworkDevice device;
        device.name=dev->name;
        device.description=dev->description;
        deviceList->append(device);
    }
    pcap_freealldevs(alldevs);
    return true;
}
