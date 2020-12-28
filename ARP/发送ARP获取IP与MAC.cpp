// 发送ARP获取IP与MAC.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#pragma pack(1) 
//以太网数据报结构
typedef struct Ethernet_head
{
	u_char DestMAC[6];    //目的MAC地址 6字节
	u_char SourMAC[6];   //源MAC地址 6字节
	u_short EthType;
};

//ARP数据报头结构
typedef struct ARPFrame_t
{
	unsigned short HardwareType; //硬件类型
	unsigned short ProtocolType; //协议类型
	unsigned char HardwareAddLen; //硬件地址长度
	unsigned char ProtocolAddLen; //协议地址长度
	unsigned short OperationField; //操作字段
	unsigned char SourceMacAdd[6]; //源mac地址
	unsigned long SourceIpAdd; //源ip地址
	unsigned char DestMacAdd[6]; //目的mac地址
	unsigned long DestIpAdd; //目的ip地址
};
//arp包结构
struct ArpPacket {
	Ethernet_head ed;
	ARPFrame_t ah;
};
//线程参数
struct sparam {
	pcap_t *adhandle;
	char *ip;
	unsigned char *mac;
	char *netmask;
};
struct gparam {
	pcap_t *adhandle;
};

struct sparam sp;
struct gparam gp;
char *myBroad;
unsigned char *m_MAC=new unsigned char[6];
char *m_IP;
char *m_mask;
#define IPTOSBUFFERS    12
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
int GetLivePC2(pcap_t *adhandle);
int _tmain(int argc, _TCHAR* argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	int num = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	time_t local_tv_sec;
	char timestr[16];
	struct pcap_pkthdr *header = new pcap_pkthdr;
	const u_char *pkt_data = new u_char;
	int res;

	//获取本机设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//错误处理
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
	}
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		/* 设备名(Name) */
		printf("%s\n", d->name);

		/* 设备描述(Description) */
		if (d->description)
			printf("\tDescription: %s\n", d->description);

		printf("\n");
	}
	//选择设备
	d = alldevs;
	cout << "输入选择的设备号：" << endl;
	cin >> num;
	for (int i = 0; i < num - 1; i++)
		d = d->next;
	ifprint(d);
	//打开指定的网络接口
	pcap_t *adhandle;
	if ((adhandle = pcap_open_live(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);
	GetSelfMac(adhandle, m_IP, m_MAC);
	printf("MyMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
		*m_MAC,
		*(m_MAC+1),
		*(m_MAC+2),
		*(m_MAC+3),
		*(m_MAC+4),
		*(m_MAC+5));

	HANDLE sendthread;      //发送ARP包线程
	HANDLE recvthread;       //接受ARP包线程
	sp.adhandle = adhandle;
	sp.ip = m_IP;
	sp.netmask = m_mask;
	sp.mac = m_MAC;
	gp.adhandle = adhandle;
	
		sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendArpPacket,
			&sp, 0, NULL);
		/*recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetLivePC, &gp,
			0, NULL);*/
		GetLivePC2(adhandle);
		
	pcap_freealldevs(alldevs);
	CloseHandle(sendthread);
	CloseHandle(recvthread);
	while (1);
	return 0;
}
/* 打印所有可用信息 */
void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) 
	{
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
			{
				m_IP = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
				printf("\tIP Address: %s\n", m_IP);
			}
			if (a->netmask)
			{
				m_mask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
				printf("\tNetmask: %s\n", m_mask);
			}
				
			if (a->broadaddr)
			{
				myBroad = iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);
				printf("\tBroadcast Address: %s\n", myBroad);
			}
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;
		default:
			//printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}

char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_REPLY       2      //ARP应答
#define HOSTNUM         255   //主机数量
// 获取自己主机的MAC地址
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac) {
	unsigned char sendbuf[42]; //arp包结构大小
	int i = -1;
	int res;
	Ethernet_head eh; //以太网帧头
	ARPFrame_t ah;  //ARP帧头
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data=new u_char;
	//将已开辟内存空间 eh.dest_mac_add 的首 6个字节的值设为值 0xff。
	memset(eh.DestMAC, 0xff, 6); //目的地址为全为广播地址
	memset(eh.SourMAC, 0x0f, 6);
	memset(ah.DestMacAdd, 0x0f, 6);
	memset(ah.SourceMacAdd, 0x00, 6);
	//htons将一个无符号短整型的主机数值转换为网络字节顺序
	eh.EthType = htons(ETH_ARP);
	ah.HardwareType = htons(ARP_HARDWARE);
	ah.ProtocolType = htons(ETH_IP);
	ah.HardwareAddLen = 6;
	ah.ProtocolAddLen = 4;
	ah.SourceIpAdd = inet_addr("100.100.100.100"); //随便设的请求方ip
	ah.OperationField = htons(ARP_REQUEST);
	ah.DestIpAdd = inet_addr(ip_addr);
	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	printf("%s", sendbuf);
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;
	}
	
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP)&& *(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY)&& *(unsigned long*)(pkt_data + 38)== inet_addr("100.100.100.100")) {
			for (i = 0; i < 6; i++) {
				ip_mac[i] = *(unsigned char *)(pkt_data + 22 + i);
			}
			printf("获取自己主机的MAC地址成功!\n");
			break;
		}
	}
	if (i == 6) {
		return 1;
	}
	else {
		return 0;
	}
}
bool flag;
DWORD WINAPI SendArpPacket(LPVOID lpParameter)
{
	sparam *spara = (sparam *)lpParameter;
	pcap_t *adhandle = spara->adhandle;
	char *ip = spara->ip;
	unsigned char *mac = spara->mac;
	char *netmask = spara->netmask;
	printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
		mac[3], mac[4], mac[5]);
	printf("自身的IP地址为:%s\n", ip);
	printf("地址掩码NETMASK为:%s\n", netmask);
	printf("\n");
	unsigned char sendbuf[42]; //arp包结构大小
	Ethernet_head eh;
	ARPFrame_t ah;
	//赋值MAC地址
	memset(eh.DestMAC, 0xff, 6);       //目的地址为全为广播地址
	memcpy(eh.SourMAC, mac, 6);
	memcpy(ah.SourceMacAdd, mac, 6);
	memset(ah.DestMacAdd, 0x00, 6);
	eh.EthType = htons(ETH_ARP);//帧类型为ARP3
	ah.HardwareType = htons(ARP_HARDWARE);
	ah.ProtocolType = htons(ETH_IP);
	ah.HardwareAddLen = 6;
	ah.ProtocolAddLen = 4;
	ah.SourceIpAdd = inet_addr(ip); //请求方的IP地址为自身的IP地址
	ah.OperationField = htons(ARP_REQUEST);
	//向局域网内广播发送arp包
	unsigned long myip = inet_addr(ip);
	unsigned long mynetmask = inet_addr(netmask);
	unsigned long hisip = htonl((myip & mynetmask));
	//向指定IP主机发送
	char desIP[16];
	printf("输入目标IP:");
	scanf("%s", &desIP);
	//char* desIP = "192.168.43.55";
	ah.DestIpAdd = htonl(inet_addr(desIP));
		//构造一个ARP请求
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &eh, sizeof(eh));
		memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
		//如果发送成功
		if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
			printf("\nPacketSend succeed\n");
		}
		else {
			printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		}
	flag = TRUE;
	return 0;
}
DWORD WINAPI GetLivePC(LPVOID lpParameter) //(pcap_t *adhandle)
{
	
	gparam *gpara = (gparam *)lpParameter;
	pcap_t *adhandle = gpara->adhandle;
	int res;
	unsigned char Mac[6];
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	while (true) {
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
			if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP)) {
				ArpPacket *recv = (ArpPacket *)pkt_data;
				if (*(unsigned short *)(pkt_data + 20) == htons(ARP_REPLY)) {
					//printf("-------------------------------------------\n");
					printf("IP地址:%d.%d.%d.%d   MAC地址:",
						recv->ah.SourceIpAdd & 255,
						recv->ah.SourceIpAdd >> 8 & 255,
						recv->ah.SourceIpAdd >> 16 & 255,
						recv->ah.SourceIpAdd >> 24 & 255);
					for (int i = 0; i < 6; i++) {
						Mac[i] = *(unsigned char *)(pkt_data + 22 + i);
						printf("%02x ", Mac[i]);
					}
					printf("\n");
				}
			}
		}
		Sleep(10);
	}
	return 0;
}
int GetLivePC2(pcap_t *adhandle) //(pcap_t *adhandle)
{

	//gparam *gpara = (gparam *)lpParameter;
	//pcap_t *adhandle = gpara->adhandle;
	int res;
	unsigned char Mac[6];
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	while (true) {
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
			if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP)) {
				ArpPacket *recv = (ArpPacket *)pkt_data;
				if (*(unsigned short *)(pkt_data + 20) == htons(ARP_REPLY)) {
					printf("IP地址:%d.%d.%d.%d   MAC地址:",
						recv->ah.SourceIpAdd & 255,
						recv->ah.SourceIpAdd >> 8 & 255,
						recv->ah.SourceIpAdd >> 16 & 255,
						recv->ah.SourceIpAdd >> 24 & 255);
					for (int i = 0; i < 6; i++) {
						Mac[i] = *(unsigned char *)(pkt_data + 22 + i);
						printf("%02x ", Mac[i]);
					}
					printf("\n");
				}
			}
		}
		Sleep(10);
	}
	return 0;
}