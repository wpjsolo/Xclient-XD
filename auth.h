#ifndef AUTH_H
#define AUTH_H
#include <QString>
#include <QObject>
#include <QThread>
#include "md5.h"
#include <assert.h>


#if defined(WIN32)
#include "pcaphelper.h"
#include <windows.h>
#define sleep(x) Sleep(x)
#define false 0
#define true 1
#else
#include <stdbool.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#endif

#define _CRT_SECURE_NO_WARNINGS 1
#define OID_802_3_PERMANENT_ADDRESS             0x01010101
#define OID_802_3_CURRENT_ADDRESS               0x01010102

#define REQUEST 1
#define RESPONSE 2
#define SUCCESS 3
#define FAILURE 4
#define H3CDATA 10

#define IDENTITY 1
#define NOTIFICATION 2
#define MD5 4
#define AVAILABLE 20

typedef unsigned char uint_8;
typedef unsigned short uint_16;
typedef unsigned int uint_32;
typedef uint_8 EAP_ID;
const uint_8 BroadcastAddr[6]	= {0xff,0xff,0xff,0xff,0xff,0xff};
const uint_8 MultcastAddr[6]	= {0x01,0x80,0xc2,0x00,0x00,0x03};
const char H3C_VERSION[16]		= "EN V2.40-0335";
const char H3C_KEY[]			= "HuaWei3COM1X";

static void SendStartPkt(pcap_t *adhandle, const uint_8 mac[]);
static void SendLogoffPkt(pcap_t *adhandle, const uint_8 mac[]);
static void SendResponseIdentity(pcap_t *adhandle,
            const uint_8 request[],
            const uint_8 ethhdr[],
            const uint_8 ip[4],
            const char    username[]);
static void SendResponseMD5(pcap_t *adhandle,
        const uint_8 request[],
        const uint_8 ethhdr[],
        const char username[],
        const char passwd[]);
static void SendResponseAvailable(pcap_t *adhandle,
        const uint_8 request[],
        const uint_8 ethhdr[],
        const uint_8 ip[4],
        const char    username[]);
static void SendResponseNotification(pcap_t *handle,
        const uint_8 request[],
        const uint_8 ethhdr[]);

static int GetMacFromDevice(uint_8 mac[6], const char *devicename);
static void GetIpFromDevice(uint_8 ip[4], const char DeviceName[]);
static void FillClientVersionArea(uint_8 area[]);
static void FillWindowsVersionArea(uint_8 area[]);
static void FillBase64Area(char area[]);
extern void MD5Calc(unsigned char *data, unsigned int len, unsigned char *output);
static void FillMD5Area(uint_8 digest[], uint_8 id, const char passwd[], const uint_8 srcMD5[]);
class Auth: public QThread
{
  Q_OBJECT

public:
    Auth();
    ~Auth();
    virtual void run();
    void InitAuth(QString username,QString password,QString device, QObject *parent = 0);
    int startAuth();
    int stopAuth();
    boolean status;
signals:
    void signal_changeBtnSlots(QString type);
private:
    QString username,password,device;
};

#endif // AUTH_H
