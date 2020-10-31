// 数据包获取.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#define LINE_LEN 16
#define MAX_ADDR_LEN 16

typedef struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct IPHeader_t//IP首部
{
	BYTE Ver_HLen;//版本
	BYTE TOS;//服务类型
	WORD TotalLen;//总长度
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
}IPHeader_t;

typedef struct Data_t
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

//IPHeader处理函数
void ip_protocol_packet_handle(const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	IPHeader_t *IPHeader;
	IPHeader = (IPHeader_t *)(pkt_data + 14);
	sockaddr_in source, dest;
	char sourceIP[MAX_ADDR_LEN], destIP[MAX_ADDR_LEN];

	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), MAX_ADDR_LEN);
	strncpy(destIP, inet_ntoa(dest.sin_addr), MAX_ADDR_LEN);

	//开始输出
	printf("Version: %d\n", IPHeader->Ver_HLen >> 4);
	printf("Header Length: %d Bytes\n", (IPHeader->Ver_HLen & 0x0f) * 4);
	printf("Tos: %d\n", IPHeader->TOS);
	printf("Total Length: %d\n", ntohs(IPHeader->TotalLen));
	printf("Identification: 0x%.4x (%i)\n", ntohs(IPHeader->ID));
	printf("Flags: %d\n", ntohs(IPHeader->Flag_Segment));
	printf("---Reserved bit: %d\n", (IPHeader->Flag_Segment) & 0x8000 >> 15);
	printf("Time to live: %d\n", IPHeader->TTL);
	printf("Protocol Type: ");

	switch (IPHeader->Protocol)
	{
	case 1:
		printf("ICMP");
		break;
	case 6:
		printf("TCP");
		break;
	case 17:
		printf("UDP");
		break;
	default:
		break;
	}
	printf(" (%d)\n", IPHeader->Protocol);
	printf("Header checkSum: 0x%.4x\n", ntohs(IPHeader->Checksum));
	printf("Source: %s\n", sourceIP);
	printf("Destination: %s\n", destIP);
}

//帧首部处理函数
void ethernet_protocol_packet_handle(const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	FrameHeader_t *ethernet_protocol;//以太网协议
	u_short ethernet_type;			//以太网类型
	u_char *mac_string;				//以太网地址

	//获取以太网数据内容
	ethernet_protocol = (FrameHeader_t*)pkt_data;
	ethernet_type = ntohs(ethernet_protocol->FrameType);

	printf("==============Ethernet Protocol=================\n");

	//以太网目标地址
	mac_string = ethernet_protocol->DesMAC;

	printf("Destination Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));

	//以太网源地址
	mac_string = ethernet_protocol->SrcMAC;

	printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));

	printf("Ethernet type: ");
	switch (ethernet_type)
	{
	case 0x0800:
		printf("%s", "IP");
		break;
	case 0x0806:
		printf("%s", "ARP");
		break;
	case 0x0835:
		printf("%s", "RARP");
		break;
	default:
		printf("%s", "Unknown Protocol");
		break;
	}
	printf(" (0x%04x)\n", ethernet_type);

	//进入IPHeader处理函数
	if (ethernet_type == 0x0800)
	{
		ip_protocol_packet_handle(pkt_header, pkt_data);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	int num=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	time_t local_tv_sec;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
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
		printf("%s ", d->name);
		num++;
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	//选择设备
	d = alldevs;
	cout << "输入选择的设备号：" << endl;
	cin >> num;
	for (int i = 0; i < num; i++)
		d = d->next;

	//打开指定的网络接口
		pcap_t *adhandle;
		Data_t *IPPacket;
		ULONG SourceIP, DestinationIP;
		if ((adhandle = pcap_open_live(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000,errbuf))==NULL)
		{
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
			pcap_freealldevs(alldevs);
			return -1;
		}
			printf("\nlistening on %s...\n", d->description);
			//开始捕获
			while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
			{
				if (res == 0)
				{
					//接收数据包超时
					continue;
				}
				//将时间戳转化为可识别格式
				local_tv_sec = header->ts.tv_sec;
				ltime = localtime(&local_tv_sec);
				strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

				//输出编号、时间戳和包长度
				printf("==============================================================================\n");
				printf("No.%d\ttime: %s\tlen: %ld\n", num, timestr, header->len);
				printf("==============================================================================\n");
				
				char temp[17];
				//输出包
				for (int i = 0; i < header->caplen; ++i)
				{
					printf("%.2x ", pkt_data[i]);
					if (isgraph(pkt_data[i]) || pkt_data[i] == ' ')
						temp[i % LINE_LEN] = pkt_data[i];
					else
						temp[i % LINE_LEN] = '.';

					if (i % LINE_LEN == 15)
					{
						temp[16] = '\0';
						printf("        ");
						printf("%s", temp);
						printf("\n");
						memset(temp, 0, LINE_LEN);
					}
				}
				printf("\n");
				//分析数据包
				ethernet_protocol_packet_handle(header,pkt_data);
					break;
			}
	
	while (1);
	return 0;
}

