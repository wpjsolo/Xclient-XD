#include "auth.h"
#include "mylog.h"
QString GetMacString(uint_8 MAC[6])
{
    QString res;
    for (int i=0;i<6;i++)
    {
        QString hexString=QString::number(MAC[i],16).toUpper();
        if (hexString.count()==1) hexString="0"+hexString;
        if(i!=5) hexString.append(":");
        res.append(hexString);
    }
    return res;
}
Auth::Auth()
{

}
Auth::~Auth()
{
}

void Auth::InitAuth(QString username,QString password,QString device,QObject *parent)
{
    this->status=true;
    this->device=device;
    this->password=password;
    this->username=username;
    QObject::disconnect(&logger,SIGNAL(SIGNAL_debug(QString)),0,0);
    QObject::connect(&logger,SIGNAL(SIGNAL_debug(QString)),parent,SLOT(SLOT_debug(QString)));
    QObject::disconnect(this,SIGNAL(signal_changeBtnSlots(QString)),0,0);
    QObject::connect(this,SIGNAL(signal_changeBtnSlots(QString)),parent,SLOT(SLOT_changeBtnSlots(QString)));
}

void Auth::run()
{
    this->startAuth();
}

int Auth::startAuth()
{
    pcap_t *adhandle;
    char	errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    char FilterStr[100];
    uint_8	MAC[6];
    const int DefaultTimeout = 500;

    this->status=true;
    emit this->signal_changeBtnSlots("Stop");

    adhandle = pcap_open_live(device.toUtf8().data(),65536,1,DefaultTimeout,errbuf);
    if (adhandle == NULL) {
        logger.error(QString::fromLocal8Bit(errbuf));
        emit this->signal_changeBtnSlots("Start");
        return -1;
    }
    GetMacFromDevice(MAC, device.toUtf8().data());
    logger.debug(GetMacString(MAC));
    sprintf_s(FilterStr,"(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
              MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
    pcap_compile(adhandle,&fcode,FilterStr,1,0xff);
    pcap_setfilter(adhandle,&fcode);

START_AUTHENTICATION:
    {
        int retcode=0;
        struct pcap_pkthdr *header= NULL;
        const uint_8 *captured = NULL;
        boolean serverIsFound=false;
        uint_8 ethhdr[14]={0};
        uint_8 ip[4]={0};

        /*Find the Server*/
        logger.debug("Client: Looking for server.");
        serverIsFound=false;
        while (!serverIsFound && this->status)
        {
            SendStartPkt(adhandle,MAC);
            retcode = pcap_next_ex(adhandle, &header, &captured);
            if (retcode==1 && captured[18]==REQUEST)
                serverIsFound = true;
            else
            {
                sleep(1);
            }
        }
        if (!this->status) {
            emit this->signal_changeBtnSlots("Start");
            return -1;
        }
        /*Answer the server*/
        memcpy(ethhdr+0, captured+6, 6);
        memcpy(ethhdr+6, MAC, 6);
        ethhdr[12] = 0x88;
        ethhdr[13] = 0x8e;
        logger.debug(
                    QString("HOST MAC: %1")
                    .arg(GetMacString(ethhdr))
                );
        if (captured[22] == NOTIFICATION)
        {
            logger.debug(QString("[%1] Server: Request Notification!").arg((int)captured[19]));
            //Response Notification
            SendResponseNotification(adhandle, captured, ethhdr);
            logger.debug(QString("[%1] Client: Response Notification.").arg((int)captured[19]));
            //Go on Request
            retcode = pcap_next_ex(adhandle, &header, &captured);
            assert(retcode==1);
            assert(captured[18] == REQUEST);
        }

        if (captured[22] == IDENTITY)
        {
            //Request Identity,Response Identity
            logger.debug(QString("[%1] Server: Request Identity!").arg((int)captured[19]));
            GetIpFromDevice(ip, device.toUtf8().data());
            SendResponseIdentity(adhandle, captured, ethhdr, ip, username.toUtf8().data());
            logger.debug(QString("[%1] Client: Response Identity.").arg((int)captured[19]));
        }
        else if (captured[22] == AVAILABLE)
        {
            //Response in particular ways
            //Request Identity,Response Identity
            logger.debug(QString("[%1] Server: Request Identity!(AVAILABLE)").arg((int)captured[19]));
            GetIpFromDevice(ip, device.toUtf8().data());
            SendResponseIdentity(adhandle, captured, ethhdr, ip, username.toUtf8().data());
            logger.debug(QString("[%1] Client: Response Identity.(AVAILABLE)").arg((int)captured[19]));
        }

        sprintf_s(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
                captured[6],captured[7],captured[8],captured[9],captured[10],captured[11],MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
        pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
        pcap_setfilter(adhandle, &fcode);

        emit this->signal_changeBtnSlots("LogOff");
        /*Heart beat packet*/
        while(true)
        {
            while (pcap_next_ex(adhandle, &header, &captured) != 1)
            {
                //Retry while error
                if (!this->status) break;
                sleep(1);
            }
            if (!this->status) break;

            if (captured[18] == REQUEST)
            {
                int index= captured[19];
                switch (captured[22])
                {
                case IDENTITY:
                    logger.debug(QString("[%1] Server: Request Identity!").arg(index));
                    GetIpFromDevice(ip, device.toUtf8().data());
                    SendResponseIdentity(adhandle, captured, ethhdr, ip, username.toUtf8().data());
                    index=captured[19];
                    logger.debug(QString("[%1] Client: Response Identity.").arg(index));
                    break;
                case AVAILABLE:
                    logger.debug(QString("[%1] Server: Request  AVAILABLE!").arg(index));
                    GetIpFromDevice(ip, device.toUtf8().data());
                    SendResponseAvailable(adhandle, captured, ethhdr, ip, username.toUtf8().data());
                    index=captured[19];
                    logger.debug(QString("[%1] Client: Response AVAILABLE.").arg(index));
                    break;
                case MD5:
                    logger.debug(QString("[%1] Server: Request MD5-Challenge!").arg(index));
                    SendResponseMD5(adhandle, captured, ethhdr,username.toUtf8().data(), password.toUtf8().data());
                    index=captured[19];
                    logger.debug(QString("[%1] Client: Response MD5-Challenge.").arg(index));
                    break;
                case NOTIFICATION:
                    logger.debug(QString("[%1] Server: Request Notification!").arg(index));
                    SendResponseNotification(adhandle, captured, ethhdr);
                    index=captured[19];
                    logger.debug(QString("[%1] Client: Response  Notification.").arg(index));
                    break;
                default:
                    logger.debug(QString("[%1] Server: Unkonwn Request (type:%2)!").arg(index).arg((int)captured[22]));
                    break;
                }
            }
            else if (captured[18] == FAILURE)
            {
                //when failure happens
                uint_8 errtype = captured[22];
                uint_8 msgsize = captured[23];
                const char *msg = (const char*) &captured[24];
                if (errtype==0x08)
                {
                    logger.debug(QString("Log Off."));
                    break;
                }
                logger.debug(QString("[%1] Server: Failure.\n").arg((int)captured[19]));
                if (errtype==0x09 && msgsize>0)
                {
                    logger.error(QString(msg));
                    break;
                }
                else
                {
                    logger.error(QString::number(errtype,16).toUpper());
                    break;
                }
                goto START_AUTHENTICATION;//just disable warning;
            }
            else if (captured[18] == SUCCESS)
            {
                logger.debug(QString("[%1] Server: Success.").arg((int)captured[19]));
                // system("njit-RefreshIP");
            }
            else
            {
                logger.debug(QString("[%1] Server: H3C data(%2)").arg((int)captured[19]).arg((int)captured[18]));
                //Other H3C data
            }
        }
        pcap_close(adhandle);
        emit this->signal_changeBtnSlots("Start");
        return 1;
    }
}
int Auth::stopAuth()
{
     pcap_t *adhandle;
     char	errbuf[PCAP_ERRBUF_SIZE];
     uint_8	MAC[6];
     const int DefaultTimeout = 500;

     adhandle = pcap_open_live(device.toUtf8().data(),65536,1,DefaultTimeout,errbuf);
     if (adhandle == NULL) {
         logger.error(QString::fromLocal8Bit(errbuf));
         return -1;
     }
     GetMacFromDevice(MAC, device.toUtf8().data());
     SendLogoffPkt(adhandle,MAC);
     return 1;
}

static
void GetIpFromDevice(uint_8 ip[4], const char DeviceName[])
{
#if defined(WIN32)
    DeviceName;
    struct hostent* hn = NULL;
    char HostName[255];
    gethostname(HostName, sizeof(HostName));
    hn = gethostbyname(HostName);
    memcpy(ip, ((struct in_addr *)hn->h_addr_list[0]), 4);
#else
    int fd;
    struct ifreq ifr;
    assert(strlen(DeviceName) <= IFNAMSIZ);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd>0);
    strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
    {
        struct sockaddr_in *p = (void*) &(ifr.ifr_addr);
        memcpy(ip, &(p->sin_addr), 4);
    }
    else
    {
        memset(ip, 0x00, 4);
    }
    close(fd);
#endif
}

static
int GetMacFromDevice(uint_8 mac[6],const char *devicename)
{
#if defined(WIN32)
    LPADAPTER lpAdapter;
    PPACKET_OID_DATA  OidData;
    BOOLEAN status;

    lpAdapter = PacketOpenAdapter((char *)devicename);

    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        return -1;
    }

    OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL) {
        return -1;
    }

    OidData->Oid = OID_802_3_CURRENT_ADDRESS;
    OidData->Length = 6;
    ZeroMemory(OidData->Data, 6);

    status = PacketRequest(lpAdapter, FALSE, OidData);
    if (status == (int)NULL) {
        return -1;
    }

    memcpy((void *)mac, (void *)OidData->Data, 6);

    free(OidData);
    PacketCloseAdapter(lpAdapter);

    return 0;
#else
    int	fd;
    int	err;
    struct ifreq	ifr;

    fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
    assert(fd != -1);

    assert(strlen(devicename) < IFNAMSIZ);
    strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;

    err = ioctl(fd, SIOCGIFHWADDR, &ifr);
    assert(err != -1);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    err = close(fd);
    assert(err != -1);
    return 0;
#endif
}


static
void SendStartPkt(pcap_t *handle, const uint_8 localmac[])
{
    uint_8 packet[18];

    // Ethernet Header (14 Bytes)
    memcpy(packet, BroadcastAddr, 6);
    memcpy(packet+6, localmac,   6);
    packet[12] = 0x88;
    packet[13] = 0x8e;

    // EAPOL (4 Bytes)
    packet[14] = 0x01;	// Version=1
    packet[15] = 0x01;	// Type=Start
    packet[16] = packet[17] =0x00;// Length=0x0000

    pcap_sendpacket(handle, packet, sizeof(packet));

    memcpy(packet, MultcastAddr, 6);
    pcap_sendpacket(handle, packet, sizeof(packet));
}

static
void SendResponseAvailable(pcap_t *handle, const uint_8 request[], const uint_8 ethhdr[], const uint_8 ip[4], const char username[])
{
    int i;
    uint_16 eaplen;
    int usernamelen;
    uint_8 response[128];

    assert(/*(EAP_Code)*/request[18] == REQUEST);
    assert(/*(EAP_Type)*/request[22] == AVAILABLE);

    // Fill Ethernet header
    memcpy(response, ethhdr, 14);

    // 802,1X Authentication
    // {
    response[14] = 0x1;	// 802.1X Version 1
    response[15] = 0x0;	// Type=0 (EAP Packet)

    // Extensible Authentication Protocol
    // {
    response[18] = /*(EAP_Code)*/ RESPONSE;	// Code
    response[19] = request[19];		// ID
    response[22] = /*(EAP_Type)*/ AVAILABLE;	// Type
    // Type-Data
    // {
    i = 23;
    response[i++] = 0x00;
    response[i++] = 0x15;
    response[i++] = 0x04;	  //
    memcpy(response+i, ip, 4);//
    i += 4;			  //
    response[i++] = 0x06;
    response[i++] = 0x07;		  //
    FillBase64Area((char*)response+i);//
    i += 28;			  //
    response[i++] = ' ';
    response[i++] = ' '; //
    usernamelen = strlen(username);
    memcpy(response+i, username, usernamelen);//
    i += usernamelen;			  //
    // }
    // }
    // }

    eaplen = htons(i-18);
    memcpy(response+16, &eaplen, sizeof(eaplen));
    memcpy(response+20, &eaplen, sizeof(eaplen));

    pcap_sendpacket(handle, response, i);
}


static
void SendResponseIdentity(pcap_t *adhandle, const uint_8 request[], const uint_8 ethhdr[], const uint_8 ip[4], const char username[])
{
    uint_8	response[128];
    size_t i;
    uint_16 eaplen;
    int usernamelen;

    assert(/*(EAP_Code)*/request[18] == REQUEST);
    assert(/*(EAP_Type)*/request[22] == IDENTITY
            ||/*(EAP_Type)*/request[22] == AVAILABLE);

    // Fill Ethernet header
    memcpy(response, ethhdr, 14);

    // 802,1X Authentication
    // {
    response[14] = 0x1;	// 802.1X Version 1
    response[15] = 0x0;	// Type=0 (EAP Packet)
    // Extensible Authentication Protocol
    // {
    response[18] = /*(EAP_Code)*/ RESPONSE;	// Code
    response[19] = request[19];		// ID
    response[22] = /*(EAP_Type)*/ IDENTITY;	// Type
    // Type-Data
    // {
    i = 23;
    response[i++] = 0x15;
    response[i++] = 0x04;
    memcpy(response+i, ip, 4);
    i += 4;
    response[i++] = 0x06;
    response[i++] = 0x07;
    FillBase64Area((char*)response+i);
    i += 28;
    response[i++] = ' ';
    response[i++] = ' ';
    usernamelen = strlen(username);
    memcpy(response+i, username, usernamelen);
    i += usernamelen;
    assert(i <= sizeof(response));
    // }
    // }
    // }


    eaplen = htons(i-18);
    memcpy(response+16, &eaplen, sizeof(eaplen));
    memcpy(response+20, &eaplen, sizeof(eaplen));


    pcap_sendpacket(adhandle, response, i);
    return;
}


static
void SendResponseMD5(pcap_t *handle, const uint_8 request[], const uint_8 ethhdr[], const char username[], const char passwd[])
{
    uint_16 eaplen;
    size_t   usernamelen;
    size_t   packetlen;
    uint_8  response[128];

    assert(/*(EAP_Code)*/request[18] == REQUEST);
    assert(/*(EAP_Type)*/request[22] == MD5);

    usernamelen = strlen(username);
    eaplen = htons(22+usernamelen);
    packetlen = 14+4+22+usernamelen; // ethhdr+EAPOL+EAP+usernamelen

    // Fill Ethernet header
    memcpy(response, ethhdr, 14);

    // 802,1X Authentication
    // {
    response[14] = 0x1;	// 802.1X Version 1
    response[15] = 0x0;	// Type=0 (EAP Packet)
    memcpy(response+16, &eaplen, sizeof(eaplen));	// Length

    // Extensible Authentication Protocol
    // {
    response[18] = /*(EAP_Code)*/ RESPONSE;// Code
    response[19] = request[19];	// ID
    response[20] = response[16];	// Length
    response[21] = response[17];	//
    response[22] = /*(EAP_Type)*/ MD5;	// Type
    response[23] = 16;		// Value-Size: 16 Bytes
    FillMD5Area(response+24, request[19], passwd, request+24);
    memcpy(response+40, username, usernamelen);
    // }
    // }

    pcap_sendpacket(handle, response, packetlen);
}


static
void SendLogoffPkt(pcap_t *handle, const uint_8 localmac[])
{
    uint_8 packet[18];

    // Ethernet Header (14 Bytes)
    memcpy(packet, MultcastAddr, 6);
    memcpy(packet+6, localmac,   6);
    packet[12] = 0x88;
    packet[13] = 0x8e;

    // EAPOL (4 Bytes)
    packet[14] = 0x01;	// Version=1
    packet[15] = 0x02;	// Type=Logoff
    packet[16] = packet[17] =0x00;// Length=0x0000

    // 发包
    pcap_sendpacket(handle, packet, sizeof(packet));
}


static
void XOR(uint_8 data[], unsigned dlen, const char key[], unsigned klen)
{
    unsigned int	i,j;

    for (i=0; i<dlen; i++)
        data[i] ^= key[i%klen];

    for (i=dlen-1,j=0;  j<dlen;  i--,j++)
        data[i] ^= key[j%klen];
}

static
void FillClientVersionArea(uint_8 area[20])
{
    uint_32 random;
    char	 RandomKey[8+1];
    random = (uint_32) time(NULL);
    sprintf_s(RandomKey, "%08x", random);
    memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
    XOR(area, 16, RandomKey, strlen(RandomKey));
    random = htonl(random);
    memcpy(area+16, &random, 4);
    XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}


static
void FillWindowsVersionArea(uint_8 area[20])
{
    const uint_8 WinVersion[20] = "r70393861";

    memcpy(area, WinVersion, 20);
    XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

static
void SendResponseNotification(pcap_t *handle, const uint_8 request[], const uint_8 ethhdr[])
{
    uint_8	response[67];
    int i;

    assert(/*(EAP_Code)*/request[18] == REQUEST);
    assert(/*(EAP_Type)*/request[22] == NOTIFICATION);

    // Fill Ethernet header
    memcpy(response, ethhdr, 14);

    // 802,1X Authentication
    // {
    response[14] = 0x1;	// 802.1X Version 1
    response[15] = 0x0;	// Type=0 (EAP Packet)
    response[16] = 0x00;	// Length
    response[17] = 0x31;	//

    // Extensible Authentication Protocol
    // {
    response[18] = /*(EAP_Code)*/ RESPONSE;	// Code
    response[19] = (EAP_ID) request[19];	// ID
    response[20] = response[16];		// Length
    response[21] = response[17];		//
    response[22] = /*(EAP_Type)*/ NOTIFICATION;	// Type

    i=23;
    /* Notification Data (44 Bytes) */
    response[i++] = 0x01; // type 0x01
    response[i++] = 22;   // lenth
    FillClientVersionArea(response+i);
    i += 20;

    response[i++] = 0x02; // type 0x02
    response[i++] = 22;   // length
    FillWindowsVersionArea(response+i);
    i += 20;
    // }
    // }

    pcap_sendpacket(handle, response, sizeof(response));
}


static
void FillBase64Area(char area[])
{
    uint_8	c1,c2,c3;
    int	i, j;
    uint_8 version[20];
    const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
    FillClientVersionArea(version);
    i = 0;
    j = 0;
    while (j < 24)
    {
        c1 = version[i++];
        c2 = version[i++];
        c3 = version[i++];
        area[j++] = Tbl[ (c1&0xfc)>>2                               ];
        area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)               ];
        area[j++] = Tbl[               ((c2&0x0f)<<2)|((c3&0xc0)>>6)];
        area[j++] = Tbl[                                c3&0x3f     ];
    }
    c1 = version[i++];
    c2 = version[i++];
    area[24] = Tbl[ (c1&0xfc)>>2 ];
    area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
    area[26] = Tbl[               ((c2&0x0f)<<2)];
    area[27] = '=';
}
static
void FillMD5Area(uint_8 digest[], uint_8 id, const char passwd[], const uint_8 srcMD5[])
{
    uint_8	msgbuf[128];
    int	passlen = strlen(passwd);
    int msglen = 1 + passlen + 16;
    assert(sizeof(msgbuf) >= msglen);
    msgbuf[0] = id;
    memcpy(msgbuf+1,passwd, passlen);
    memcpy(msgbuf+1+passlen, srcMD5, 16);
    MD5Calc(msgbuf, msglen, digest);
}

