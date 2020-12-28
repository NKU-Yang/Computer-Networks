
// SimperRouterDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "SimperRouter.h"
#include "SimperRouterDlg.h"
#include "pcap.h"
#include "afxdialogex.h"
#include "afxmt.h"
#include "afxtempl.h"
#include <stdlib.h>
#include <string.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define		MAX_IF			5     // 最大接口数目

#pragma pack(1)
typedef struct FrameHeader_t  {	  // 帧首部
    UCHAR	DesMAC[6];	          // 目的地址
    UCHAR	SrcMAC[6];	          // 源地址
    USHORT	FrameType;	          // 帧类型
} FrameHeader_t;

typedef struct ARPFrame_t {		  // ARP帧
	FrameHeader_t	FrameHeader;  // 帧首部
    WORD			HardwareType; // 硬件类型
	WORD			ProtocolType; // 协议类型
	BYTE			HLen;         // 硬件地址长度
	BYTE			PLen;         // 协议地址长度
	WORD			Operation;    // 操作值
	UCHAR			SendHa[6];    // 源MAC地址
	ULONG			SendIP;       // 源IP地址
	UCHAR			RecvHa[6];    // 目的MAC地址
	ULONG			RecvIP;       // 目的IP地址
} ARPFrame_t;

typedef struct IPHeader_t {		  // IP首部
	BYTE	Ver_HLen;             // 版本+头部长度
	BYTE	TOS;                  // 服务类型
	WORD	TotalLen;             // 总长度
	WORD	ID;                   // 标识
	WORD	Flag_Segment;         // 标志+片偏移
	BYTE	TTL;                  // 生存时间
	BYTE	Protocol;             // 协议
	WORD	Checksum;             // 头部校验和
	ULONG	SrcIP;                // 源IP地址
	ULONG	DstIP;                // 目的IP地址
} IPHeader_t;

typedef struct ICMPHeader_t {     // ICMP首部
	BYTE    Type;                 // 类型
	BYTE    Code;                 // 代码
	WORD    Checksum;             // 校验和
	WORD    Id;                   // 标识
	WORD    Sequence;             // 序列号
} ICMPHeader_t;

typedef struct IPFrame_t {	      // IP帧
	FrameHeader_t	FrameHeader;  // 帧首部
	IPHeader_t		IPHeader;     // IP首部
} IPFrame_t;

#pragma pack()

typedef struct ip_t {             // 网络地址
	ULONG			IPAddr;       // IP地址
	ULONG			IPMask;       // 子网掩码
} ip_t;

typedef struct  IfInfo_t {	      // 接口信息
	char*		DeviceName;   // 设备名
	CString			Description;  // 设备描述
	UCHAR			MACAddr[6];   // MAC地址
	CArray <ip_t,ip_t&>	ip;       // IP地址列表
	pcap_t			*adhandle;    // pcap句柄
} IfInfo_t;

typedef struct SendPacket_t {	  // 发送数据包结构
	int				len;          // 长度
	BYTE			PktData[2000];// 数据缓存
	ULONG			TargetIP;     // 目的IP地址
	UINT_PTR		n_mTimer;     // 定时器
	UINT			IfNo;         // 接口序号
} SendPacket_t;

typedef struct RouteTable_t {	  // 路由表结构
	ULONG	Mask;                 // 子网掩码
	ULONG	DstIP;                // 目的地址
	ULONG	NextHop;              // 下一跳步
	UINT	IfNo;                 // 接口序号
} RouteTable_t;

typedef struct IP_MAC_t {         // IP-MAC地址映射结构
	ULONG	IPAddr;               // IP地址
	UCHAR	MACAddr[6];           // MAC地址
} IP_MAC_t;


// 全局变量
/*************************************************************************/

IfInfo_t	IfInfo[MAX_IF];	      // 接口信息数组
int			IfCount;              // 接口个数
UINT_PTR    TimerCount;           // 定时器个数

CList <SendPacket_t, SendPacket_t&> SP;           // 发送数据包缓存队列
CList <IP_MAC_t, IP_MAC_t&> IP_MAC;               // IP-MAC地址映射列表
CList <RouteTable_t, RouteTable_t&> RouteTable;   // 路由表

CRouterDlg	*pDlg;                // 对话框指针

CMutex mMutex(0,0,0);           //互斥
								//CMutex( 
								//BOOL bInitiallyOwn /* = FALSE */,    //用来指定互斥体对象初始状态是锁定(TRUE)还是非锁定(FALSE) 
								//LPCTSTR lpszName /* = NULL */,        //用来指定互斥体的名称 
								//LPSECURITY_ATTRIBUTES lpsaAttribute /* = NULL */        //为一个指向SECURITY_ATTRIBUTES结构的指针 
/*************************************************************************/


// 全局函数
/*************************************************************************/

// IP地址转换
CString IPntoa(ULONG nIPAddr);

// MAC地址转换
CString MACntoa(UCHAR *nMACAddr);

// MAC地址比较
bool cmpMAC(UCHAR *MAC1, UCHAR *MAC2);

// MAC地址复制
void cpyMAC(UCHAR *MAC1, UCHAR *MAC2);

// MAC地址设置
void setMAC(UCHAR *MAC, UCHAR ch);

// IP地址查询
bool IPLookup(ULONG ipaddr, UCHAR *p);


// 数据包捕获线程
UINT Capture(PVOID pParam);

// 获取本地接口MAC地址线程
UINT CaptureLocalARP(PVOID pParam);

// 发送ARP请求
void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP);

// 查询路由表
DWORD RouteLookup(UINT &ifNO, DWORD desIP, CList <RouteTable_t, RouteTable_t&> routeTable);

// 处理ARP数据包
void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data);

// 处理IP数据包
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data);

// 处理ICMP数据包
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data);

// 检查IP数据包头部校验和是否正确
int IsChecksumRight(char * buffer);

// 计算校验和
unsigned short ChecksumCompute(unsigned short *buffer, int size);

/*************************************************************************/



// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRouterDlg 对话框



CRouterDlg::CRouterDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CRouterDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRouterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_Log);
	DDX_Control(pDX, IDC_LIST2, m_RouteTable);
	DDX_Control(pDX, IDC_IPADDRESS2, m_Mask);
	DDX_Control(pDX, IDC_IPADDRESS1, m_Destination);
	DDX_Control(pDX, IDC_IPADDRESS3, m_NextHop);
	DDX_Control(pDX, IDC_LIST3, mc_dev);
}

BEGIN_MESSAGE_MAP(CRouterDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, &CRouterDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_ADD, &CRouterDlg::OnBnClickedAdd)
	ON_BN_CLICKED(IDC_DEL, &CRouterDlg::OnBnClickedDel)
	ON_BN_CLICKED(IDC_RETURN, &CRouterDlg::OnBnClickedReturn)
	ON_WM_DESTROY()
END_MESSAGE_MAP()


// CRouterDlg 消息处理程序

BOOL CRouterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	CRouterApp* pApp = (CRouterApp*)AfxGetApp();
	pDlg = (CRouterDlg*)pApp->m_pMainWnd;
	
	char	errbuf[PCAP_ERRBUF_SIZE], strbuf[1000];

	// 获得本机的设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /*无需认证*/, &m_alldevs, errbuf) == -1)
    {
		// 错误，返回错误信息
        sprintf_s(strbuf, "pcap_findalldevs_ex错误: %s", errbuf);
		//MessageBox(strbuf);
		PostMessage(WM_QUIT, 0, 0);
    }

	for(m_selectdevs = m_alldevs; m_selectdevs != NULL; m_selectdevs= m_selectdevs->next)      //显示接口列表
			mc_dev.AddString(CString(m_selectdevs->name));	//利用d->name获取该网络接口设备的名字
	
	mc_dev.SetCurSel(0);
	mc_dev.SetHorizontalExtent(1600);
	m_Log.SetHorizontalExtent(1600);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CRouterDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CRouterDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CRouterDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CRouterDlg::OnBnClickedStart()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_START)->EnableWindow(FALSE);   
	mc_dev.EnableWindow(FALSE);

	// 获取本机的接口列表
	pcap_addr_t			*a;
	struct bpf_program	fcode;
    char				errbuf[PCAP_ERRBUF_SIZE], strbuf[1000];
	int					i, j, k;
	ip_t				ipaddr;
	UCHAR				srcMAC[6];
	ULONG				srcIP;

	i = 0; 
	j = 0; 
	k = 0;

	//选择接口！！！！！！！！！！！！！
	int N=mc_dev.GetCurSel();//获取listbox被选中的行的数目
	m_selectdevs=m_alldevs;
	while(N--)
		m_selectdevs=m_selectdevs->next;

	IfInfo[0].DeviceName = m_selectdevs->name;
	IfInfo[0].Description = m_selectdevs->description;
	for(a = m_selectdevs->addresses; a; a = a->next)	
	{
		if (a->addr->sa_family == AF_INET)
		{
           	ipaddr.IPAddr = (((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
			ipaddr.IPMask = (((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
			IfInfo[0].ip.Add(ipaddr);
			j++;	
		}
	}	

	// 不符合路由器IP地址数目要求
	if (j < 2)
	{
		MessageBox(L"该路由程序要求本地主机至少应具有2个IP地址");
		GetDlgItem(IDC_START)->EnableWindow(TRUE);   
		mc_dev.EnableWindow(TRUE);
		return;
	}

	// 保存实际的网卡数
	IfCount = 1;//IfCount = i;	


	// 打开接口
    for (i=0; i < IfCount; i++)
	{

		if ( (IfInfo[i].adhandle = pcap_open(IfInfo[i].DeviceName, // 设备名
			                       65536,                          // 最大包长度
					               PCAP_OPENFLAG_PROMISCUOUS,      // 混杂模式
						           1000,                           // 超时时间
							       NULL,                           // 远程认证
								   errbuf                          // 错误缓存
								 ) ) == NULL)
		{
			// 错误，显示错误信息
			sprintf_s(strbuf, "接口未能打开。WinPcap不支持%s。", IfInfo[i].DeviceName);
			return;
		}
	}

	// 开启数据包捕获线程，获取本地接口的MAC地址，线程数目为网卡个数
	CWinThread* pthread;
	for (i = 0; i < IfCount; i++)
	{
		pthread = AfxBeginThread(CaptureLocalARP, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if(!pthread)
		{
			MessageBox(L"创建数据包捕获线程失败！");
			PostMessage(WM_QUIT, 0, 0);
		}
	}
	// 将列表中网卡硬件地址清0
	for (i = 0; i < IfCount; i++)
	{
		setMAC(IfInfo[i].MACAddr, 0);
	}

	// 为得到真实网卡地址，使用虚假的MAC地址和IP地址向本机发送ARP请求
	setMAC(srcMAC, 66);							// 设置虚假的MAC地址
	srcIP = inet_addr("112.112.112.112");		// 设置虚假的IP地址
	for (i = 0; i < IfCount; i++)
	{
		ARPRequest(IfInfo[i].adhandle, srcMAC, srcIP, IfInfo[i].ip[0].IPAddr);
	}
		
	j = 0;		

	// 确保所有接口的MAC地址完全收到
	setMAC(srcMAC, 0);
	do {
		Sleep(3000);	
		k = 0;
		for (i = 0; i < IfCount; i++)
		{
			if (!cmpMAC(IfInfo[i].MACAddr, srcMAC))
			{
				k++;
				continue;
			}
			else
			{
				break;
			}
		}
	} while (!((j++ > 10) || (k == IfCount)));

    if (k != IfCount)
	{
		MessageBox(L"至少有一个接口的MAC地址没能得到！");
		PostMessage(WM_QUIT, 0, 0);
	}

	// 日志输出接口信息
	for (i = 0; i < IfCount; i++)
	{
		m_Log.InsertString(-1,L"接口:");
		m_Log.InsertString(-1,L"  设备名：" + CString(IfInfo[i].DeviceName));
		m_Log.InsertString(-1,L"  设备描述：" + IfInfo[i].Description);
		m_Log.InsertString(-1,(L"  MAC地址：" + MACntoa(IfInfo[i].MACAddr)));
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			m_Log.InsertString(-1,(L"    IP地址："+IPntoa(IfInfo[i].ip[j].IPAddr)));
		}
	}

	// 初始化路由表并显示
	RouteTable_t rt;
	for (i = 0; i < IfCount; i++)
	{
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			rt.IfNo = i;
			rt.DstIP = IfInfo[i].ip[j].IPAddr  & IfInfo[i].ip[j].IPMask;
			rt.Mask  = IfInfo[i].ip[j].IPMask;
			rt.NextHop = 0;	// 直接投递
			RouteTable.AddTail(rt);
			m_RouteTable.InsertString(-1, IPntoa(rt.Mask) + " -- " + IPntoa(rt.DstIP) + " -- " + IPntoa(rt.NextHop) + "  (直接投递)");
		}
	}

	// 设置过滤规则:仅仅接收arp响应帧和需要路由的帧
	CString Filter, Filter0, Filter1;
	Filter1 = "(";
	for (i = 0; i < IfCount; i++)
	{
		Filter0 += L"(ether dst " + MACntoa(IfInfo[i].MACAddr) + L")";
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++){
			Filter1 += L"(ip dst host " + IPntoa(IfInfo[i].ip[j].IPAddr) + L")";
			if (((j == (IfInfo[i].ip.GetSize() -1))) && (i == (IfCount-1))) 
				Filter1 += ")";
			else 
				Filter1 += " or ";
		}
		if (i != (IfCount-1))	
			Filter0 += " or ";
	}
	Filter = Filter0 + L" and ((arp and (ether[21]=0x2)) or (not" + Filter1 + L"))";

	for(int i=0;i<Filter.GetLength();i++)
	{
		strbuf[i]=char(Filter[i]);
	}
	strbuf[Filter.GetLength()]='\0';

	for (i = 0; i < IfCount; i++)
	{
		if ((pcap_compile(IfInfo[i].adhandle , &fcode, strbuf, 1, IfInfo[i].ip[0].IPMask) <0 )||(pcap_setfilter(IfInfo[i].adhandle, &fcode)<0))
		{
			MessageBox(Filter+L"过滤规则编译不成功，请检查书写的规则语法是否正确！设置过滤器错误！");
			PostMessage(WM_QUIT,0,0);
		}
	}
	
	// 不再需要该设备列表,释放之
	pcap_freealldevs(m_alldevs);	

	TimerCount = 1;

	// 开始捕获数据包
	for (i=0; i < IfCount; i++)
	{
		pthread = AfxBeginThread(Capture, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if(!pthread)
		{
			MessageBox(L"创建数据包捕获线程失败！");
			PostMessage(WM_QUIT, 0, 0);			
		}
	}
	m_Log.AddString(L">>>>>>转发数据报开始！");
}

// 插入路由表项
void CRouterDlg::OnBnClickedAdd()
{
	// TODO: 在此添加控件通知处理程序代码
	bool flag;
	int i, j;
	DWORD ipaddr;
	RouteTable_t rt;
	
	m_NextHop.GetAddress(ipaddr);
	ipaddr = htonl(ipaddr);

	// 检查合法性
	flag = false;
	for (i=0; i < IfCount; i++)
	{
		for (j = 0; j < IfInfo[i].ip.GetSize(); j++)
		{
			if (((IfInfo[i].ip[j].IPAddr) & (IfInfo[i].ip[j].IPMask)) == ((IfInfo[i].ip[j].IPMask) & ipaddr))
			{
				rt.IfNo = i;
				// 记录子网掩码
				m_Mask.GetAddress(ipaddr); 
				rt.Mask = htonl(ipaddr);
				// 记录目的IP
				m_Destination.GetAddress(ipaddr);
				rt.DstIP = htonl(ipaddr);
				// 记录下一跳
				m_NextHop.GetAddress(ipaddr);
				rt.NextHop = htonl(ipaddr);
				// 把该条路由表项添加到路由表
				RouteTable.AddTail(rt);

				// 在路由表窗口中显示该路由表项
				m_RouteTable.InsertString(-1, IPntoa(rt.Mask) + " -- " 
					+ IPntoa(rt.DstIP) + " -- " + IPntoa(rt.NextHop));
				flag = true;
			}
		}
	}
	if (!flag) 
	{
		MessageBox(L"输入错误，请重新输入！");
	}
}


// 删除路由表项
void CRouterDlg::OnBnClickedDel()
{
	// TODO: 在此添加控件通知处理程序代码
	int	i;
	char str[100], ipaddr[20];
	ULONG mask, destination, nexthop;
	RouteTable_t rt;
	POSITION pos, CurrentPos;

	str[0] = NULL;
	ipaddr[0] = NULL;
	if ((i = m_RouteTable.GetCurSel()) == LB_ERR) 
	{
		return;
	}

	CString STR;
	m_RouteTable.GetText(i, STR);
	
	for(int i=0;i<STR.GetLength();i++)
		str[i]=STR[i];
	str[STR.GetLength()]='\0';


	// 取得子网掩码选项
	strncat_s(ipaddr, str, 15);
	mask = inet_addr(ipaddr);
	// 取得目的地址选项
	ipaddr[0] = 0;
	strncat_s(ipaddr, &str[19], 15);
	destination = inet_addr(ipaddr);
	// 取得下一跳选项
	ipaddr[0] = 0;
	strncat_s(ipaddr, &str[38], 15);
	nexthop = inet_addr(ipaddr);

	if (nexthop == 0)
	{
		MessageBox(L"直接连接路由，不允许删除！");
		return;
	}
	
	// 把该路由表项从路由表窗口中删除
	m_RouteTable.DeleteString(i);

	// 路由表中没有需要处理的内容，则返回
	if (RouteTable.IsEmpty()) 
	{
		return;
	}

	// 遍历路由表,把需要删除的路由表项从路由表中删除
	pos = RouteTable.GetHeadPosition();	
	for (i=0; i<RouteTable.GetCount(); i++)
	{					
		CurrentPos = pos;
		rt = RouteTable.GetNext(pos);

		if ((rt.Mask == mask) && (rt.DstIP == destination) && (rt.NextHop == nexthop))
		{
			RouteTable.RemoveAt(CurrentPos);
			return;
		}
	}
}


void CRouterDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	// TODO: 在此处添加消息处理程序代码
	SP.RemoveAll();
	IP_MAC.RemoveAll();
	RouteTable.RemoveAll();

	for (int i=0; i<IfCount; i++)
	{
		IfInfo[i].ip.RemoveAll();
	}
}

void CRouterDlg::OnBnClickedReturn()
{
	// TODO: 在此添加控件通知处理程序代码
	m_Log.ResetContent();//清除原有框的内容
	GetDlgItem(IDC_START)->EnableWindow(TRUE);   
	mc_dev.EnableWindow(TRUE);
}

void CRouterDlg::OnTimer(UINT nIDEvent) 
{
	// TODO: Add your message handler code here and/or call default
	SendPacket_t sPacket;
	POSITION pos, CurrentPos;
	IPFrame_t *IPf;

	// 没有需要处理的内容
	if (SP.IsEmpty()) 
	{
		return;	
	}
	
	mMutex.Lock(INFINITE);
	// 遍历转发缓存区
	pos = SP.GetHeadPosition();	
	for (int i = 0; i < SP.GetCount(); i++)
	{					
		CurrentPos = pos;
		sPacket = SP.GetNext(pos);
		if (sPacket.n_mTimer == nIDEvent)
		{
		    IPf = (IPFrame_t *)sPacket.PktData;
			// 日志输出信息
			m_Log.InsertString(-1, L"IP数据报在转发队列中等待10秒后还未能被转发");
			m_Log.InsertString(-1, (L"    定时器中删除该IP数据报：" + IPntoa(IPf->IPHeader.SrcIP) + L"->" 
				+ IPntoa(IPf->IPHeader.DstIP) + "  " +  MACntoa(IPf->FrameHeader.SrcMAC) 
				+ L"->xx:xx:xx:xx:xx:xx"));

			KillTimer(sPacket.n_mTimer);
			SP.RemoveAt(CurrentPos);			
		}
	}
	mMutex.Unlock();
	
	CDialog::OnTimer(nIDEvent);
}

// 获取本地接口MAC地址线程
UINT CaptureLocalARP(PVOID pParam)
{
	int					res;
	struct pcap_pkthdr	*header;
	const u_char		*pkt_data;
	IfInfo_t			*pIfInfo;
	ARPFrame_t			*ARPFrame;
	CString				DisplayStr;

	pIfInfo = (IfInfo_t *)pParam;

	while (true)
	{
		res = pcap_next_ex( pIfInfo->adhandle , &header, &pkt_data);
		// 超时
        if (res == 0) 
			continue;           
		if (res > 0)
		{
			ARPFrame = (ARPFrame_t *) (pkt_data);
			// 得到本接口的MAC地址
			if ((ARPFrame->FrameHeader.FrameType == htons(0x0806)) 
				&& (ARPFrame->Operation == htons(0x0002)) 
				&& (ARPFrame->SendIP == pIfInfo->ip[0].IPAddr)) 
			{
				cpyMAC(pIfInfo->MACAddr, ARPFrame->SendHa);
				return 0;
			}
		}
	}
}

// 数据包捕获线程
UINT Capture(PVOID pParam)
{
	int					res;
	IfInfo_t			*pIfInfo;
	struct pcap_pkthdr	*header;
	const u_char		*pkt_data;
	
	pIfInfo = (IfInfo_t *)pParam;

	// 开始正式接收并处理帧
	while (true)	
	{
		res = pcap_next_ex( pIfInfo->adhandle, &header, &pkt_data);
			    
		if (res == 1)
		{
			FrameHeader_t	*fh;
			fh = (FrameHeader_t *) pkt_data;
			switch (ntohs(fh->FrameType))
			{
				case 0x0806:
				
					ARPFrame_t *ARPf;
					ARPf = (ARPFrame_t *)pkt_data;
					
					// ARP包，转到ARP包处理函数
					ARPPacketProc(header, pkt_data);
					break;
				
				case 0x0800:
					
					IPFrame_t *IPf;
					IPf = (IPFrame_t*) pkt_data;

					// IP包，转到IP包处理函数
					IPPacketProc(pIfInfo, header, pkt_data);
					break;
				default: 
					break;
			}
		}
		else if (res == 0)	// 超时
		{
			continue;
		}
		else
		{
			AfxMessageBox(L"pcap_next_ex函数出错!");
		}
	}
	return 0;
}

// 发送ARP请求
void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP)
{
	ARPFrame_t	ARPFrame;
	int			i;

	for (i=0; i<6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 255;
		ARPFrame.FrameHeader.SrcMAC[i] = srcMAC[i];
		ARPFrame.SendHa[i] = srcMAC[i];
		ARPFrame.RecvHa[i] = 0;
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);
	ARPFrame.SendIP = srcIP;
	ARPFrame.RecvIP = targetIP;

    pcap_sendpacket(adhandle, (u_char *) &ARPFrame, sizeof(ARPFrame_t));
}

// 把IP地址转换成点分十进制形式
CString IPntoa(ULONG nIPAddr)
{
	char		strbuf[50];
	u_char		*p;
	CString		str;

	p = (u_char *) &nIPAddr;
	sprintf_s(strbuf,"%03d.%03d.%03d.%03d", p[0], p[1], p[2], p[3]);
	str = strbuf;
	return str;
}

// 把MAC地址转换成“%02X:%02X:%02X:%02X:%02X:%02X”的格式
CString MACntoa(UCHAR *nMACAddr)
{
	char		strbuf[50];
	CString		str;

	sprintf_s(strbuf,"%02X:%02X:%02X:%02X:%02X:%02X", nMACAddr[0], nMACAddr[1], 
		nMACAddr[2], nMACAddr[3], nMACAddr[4], nMACAddr[5]);
	str = strbuf;
	return str;
}

// 比较两个MAC地址是否相同
bool cmpMAC(UCHAR *MAC1, UCHAR *MAC2)
{
	for (int i=0; i<6; i++)
	{
		if (MAC1[i]==MAC2[i]) 
		{
			continue;
		}
		else 
		{
			return false;
		}
	}
	return true;
}

void cpyMAC(UCHAR *MAC1, UCHAR *MAC2)
{
	for (int i=0; i<6; i++) 
	{
		MAC1[i]=MAC2[i];
	}
}

void setMAC(UCHAR *MAC, UCHAR ch)
{
	for (int i=0; i<6; i++) 
	{
		MAC[i] = ch;
	}
	return;
}

// 查询IP-MAC映射表
bool IPLookup(ULONG ipaddr, UCHAR *p)
{
	IP_MAC_t	ip_mac;
	POSITION	pos;

	if (IP_MAC.IsEmpty()) return false;

	pos = IP_MAC.GetHeadPosition();
    for (int i = 0; i<IP_MAC.GetCount(); i++)
	{
        ip_mac = IP_MAC.GetNext(pos);
		if (ipaddr == ip_mac.IPAddr)
		{
			for (int j = 0; j < 6; j++)
			{
				p[j] = ip_mac.MACAddr[j];
			}
			return true;
		}
	}
	return false;
}

// 处理ARP数据包
void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data)
{
	bool			flag;
	ARPFrame_t		*ARPf;
	IPFrame_t		*IPf;
	SendPacket_t	sPacket;
	POSITION		pos, CurrentPos;
	IP_MAC_t		ip_mac;
	UCHAR			macAddr[6];
	
	ARPf = (ARPFrame_t *)pkt_data;
	
	if (ARPf->Operation == ntohs(0x0002))
	{
		pDlg->m_Log.AddString(L"----------------------------------------------------------------------------------");
		pDlg->m_Log.InsertString(-1, L"收到ARP响应包");
		pDlg->m_Log.InsertString(-1, (L"   ARP "+(IPntoa(ARPf->SendIP))+L" -- "
				+MACntoa(ARPf->SendHa)));
		// IP－MAC地址映射表中已经存在该对应关系
		if (IPLookup(ARPf->SendIP, macAddr)) 
		{
			pDlg->m_Log.InsertString(-1, L"   该对应关系已经存在于IP－MAC地址映射表中");
			return;	
		}		
		else
		{
			ip_mac.IPAddr = ARPf->SendIP;	
			memcpy(ip_mac.MACAddr, ARPf->SendHa, 6);
			// 将IP-MAC映射关系存入表中		
			IP_MAC.AddHead(ip_mac);

			// 日志输出信息
			pDlg->m_Log.InsertString(-1,L"   将该对应关系存入IP－MAC地址映射表中");
		}
	
		mMutex.Lock(INFINITE);
		do{		
			// 查看是否能转发缓存中的IP数据报
			flag = false;

			// 没有需要处理的内容
			if (SP.IsEmpty()) 
			{
				break;	
			}

			// 遍历转发缓存区
			pos = SP.GetHeadPosition();	
			for (int i=0; i < SP.GetCount(); i++)
			{					
				CurrentPos = pos;
				sPacket = SP.GetNext(pos);

				if (sPacket.TargetIP == ARPf->SendIP)
				{
					IPf = (IPFrame_t *) sPacket.PktData;
					cpyMAC(IPf->FrameHeader.DesMAC, ARPf->SendHa);

					for(int t=0; t<6; t++)
					{
						IPf->FrameHeader.SrcMAC[t] = IfInfo[sPacket.IfNo].MACAddr[t];
					}
					// 发送IP数据包
					pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *) sPacket.PktData, sPacket.len);

					SP.RemoveAt(CurrentPos);
					
					// 日志输出信息
					pDlg->m_Log.InsertString(-1, L"   转发缓存区中目的地址是该MAC地址的IP数据包");
					pDlg->m_Log.InsertString(-1, (L"     发送IP数据包："+IPntoa(IPf->IPHeader.SrcIP) + L"->" 
						+ IPntoa(IPf->IPHeader.DstIP) + "  " + MACntoa(IPf->FrameHeader.SrcMAC )
						+L"->"+MACntoa(IPf->FrameHeader.DesMAC)));

					flag = true;
					break;
				}
			}
		} while(flag);

		mMutex.Unlock();
	}
}

// 查询路由表
DWORD RouteLookup(UINT &ifNO, DWORD desIP, CList <RouteTable_t, RouteTable_t&> *routeTable)
{
	// desIP为网络序
	DWORD	MaxMask = 0;	// 获得最大的子网掩码的地址，没有获得时初始化为-1
	int		Index = -1;		// 获得最大的子网掩码的地址对应的路由表索引，以便获得下一站路由器的地址

	POSITION		pos;
	RouteTable_t	rt;
	DWORD tmp;

	pos = routeTable->GetHeadPosition(); 
	for (int i=0; i < routeTable->GetCount(); i++)
	{
		rt = routeTable->GetNext(pos);
		if ((desIP & rt.Mask) == rt.DstIP)
		{
			Index = i;

			if(rt.Mask >= MaxMask)
			{
				ifNO = rt.IfNo;

				if (rt.NextHop == 0)	// 直接投递
				{
					tmp = desIP;
				}
				else
				{	
					tmp = rt.NextHop;
				}
			}	
		}
	}

	if(Index == -1)				// 目的不可达
	{
		return -1;
	}
	else		// 找到了下一跳地址
	{
		return tmp;
	}		
}

// 处理IP数据包
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data)
{
	pDlg->m_Log.AddString(L"----------------------------------------------------------------------------------");
	IPFrame_t		*IPf;
	SendPacket_t	sPacket;

	IPf = (IPFrame_t *) pkt_data;
	
	pDlg->m_Log.InsertString(-1, (L"收到IP数据包:" + IPntoa(IPf->IPHeader.SrcIP) + L"->" 
		+ IPntoa(IPf->IPHeader.DstIP)));
	
	// ICMP超时
	if (IPf->IPHeader.TTL <= 0)
	{
		ICMPPacketProc(pIfInfo, 11, 0, pkt_data);
		return;
	}

	IPHeader_t *IpHeader = &(IPf->IPHeader);
	// ICMP差错
	if (IsChecksumRight((char *)IpHeader) == 0)
	{
		// 日志输出信息
		pDlg->m_Log.InsertString(-1, L"   IP数据包包头校验和错误，丢弃数据包");
		return;
	}

	// 路由查询
	DWORD nextHop;		// 经过路由选择算法得到的下一站目的IP地址
	UINT ifNo;			// 下一跳的接口序号
	// 路由查询
	if((nextHop = RouteLookup(ifNo, IPf->IPHeader.DstIP, &RouteTable)) == -1)
	{
		// ICMP目的不可达
		ICMPPacketProc(pIfInfo, 3, 0, pkt_data);
		return;
	}
	else
	{
		sPacket.IfNo = ifNo;
		sPacket.TargetIP = nextHop;

		cpyMAC(IPf->FrameHeader.SrcMAC, IfInfo[sPacket.IfNo].MACAddr);

		// TTL减1
		IPf->IPHeader.TTL -= 1;
			
		unsigned short check_buff[sizeof(IPHeader_t)];
		// 设IP头中的校验和为0
		IPf->IPHeader.Checksum = 0;                                      
	
		memset(check_buff, 0, sizeof(IPHeader_t));
		IPHeader_t * ip_header = &(IPf->IPHeader);
		memcpy(check_buff, ip_header, sizeof(IPHeader_t));
 
		// 计算IP头部校验和
		IPf->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
		
		// IP-MAC地址映射表中存在该映射关系
		if (IPLookup(sPacket.TargetIP, IPf->FrameHeader.DesMAC)) 
		{
			memcpy(sPacket.PktData, pkt_data, header->len);
			sPacket.len = header->len;
			if(pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *) sPacket.PktData, sPacket.len) != 0)
			{
				// 错误处理
				AfxMessageBox(L"发送IP数据包时出错!");
				return;
			}

			// 日志输出信息
			pDlg->m_Log.InsertString(-1,L"   转发IP数据包：");
			pDlg->m_Log.InsertString(-1,(L"   "+IPntoa(IPf->IPHeader.SrcIP) + L"->" 
				+ IPntoa(IPf->IPHeader.DstIP) + "  " + MACntoa(IPf->FrameHeader.SrcMAC )
				+ L"->" + MACntoa(IPf->FrameHeader.DesMAC))); 
		}
		// IP-MAC地址映射表中不存在该映射关系
		else
		{
			if (SP.GetCount() < 65530)		// 存入缓存队列
			{
				sPacket.len = header->len;	
				// 将需要转发的数据报存入缓存区
				memcpy(sPacket.PktData, pkt_data, header->len);
						
				// 在某一时刻只允许一个线程维护链表
				mMutex.Lock(INFINITE);	

				sPacket.n_mTimer = TimerCount;
				if (TimerCount++ > 65533) 
				{
					TimerCount = 1;
				}
				pDlg->SetTimer(sPacket.n_mTimer, 10000, NULL);
				SP.AddTail(sPacket);
			
				mMutex.Unlock();

				// 日志输出信息
				pDlg->m_Log.InsertString(-1,L"   缺少目的MAC地址，将IP数据包存入转发缓冲区");
				pDlg->m_Log.InsertString(-1, (L"   存入转发缓冲区的数据包为："+IPntoa(IPf->IPHeader.SrcIP) 
					+ L"->" + IPntoa(IPf->IPHeader.DstIP) + L"  " + MACntoa(IPf->FrameHeader.SrcMAC)
					+ L"->xx:xx:xx:xx:xx:xx")); 
				pDlg->m_Log.InsertString(-1, L"   发送ARP请求");

				// 发送ARP请求
				ARPRequest(IfInfo[sPacket.IfNo].adhandle, IfInfo[sPacket.IfNo].MACAddr, 
					IfInfo[sPacket.IfNo].ip[1].IPAddr, sPacket.TargetIP);
			}	
			else	// 如缓存队列太长，抛弃该报
			{
				// 日志输出信息
				pDlg->m_Log.InsertString(-1, L"   转发缓冲区溢出，丢弃IP数据包");
				pDlg->m_Log.InsertString(-1, (L"   丢弃的IP数据包为：" + IPntoa(IPf->IPHeader.SrcIP) + L"->" 
					+ IPntoa(IPf->IPHeader.DstIP) + L"  " + MACntoa(IPf->FrameHeader.SrcMAC)
					+ L"->xx:xx:xx:xx:xx:xx")); 
			}
		}	
	}
}


// 发送ICMP数据包
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data)
{
	u_char * ICMPBuf = new u_char[70];

	// 填充帧首部
	memcpy(((FrameHeader_t *)ICMPBuf)->DesMAC, ((FrameHeader_t *)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t *)ICMPBuf)->SrcMAC, ((FrameHeader_t *)pkt_data)->DesMAC, 6);
	((FrameHeader_t *)ICMPBuf)->FrameType = htons(0x0800);

	// 填充IP首部
	((IPHeader_t *)(ICMPBuf+14))->Ver_HLen = ((IPHeader_t *)(pkt_data+14))->Ver_HLen;
	((IPHeader_t *)(ICMPBuf+14))->TOS = ((IPHeader_t *)(pkt_data+14))->TOS;
	((IPHeader_t *)(ICMPBuf+14))->TotalLen = htons(56);
	((IPHeader_t *)(ICMPBuf+14))->ID = ((IPHeader_t *)(pkt_data+14))->ID;
	((IPHeader_t *)(ICMPBuf+14))->Flag_Segment = ((IPHeader_t *)(pkt_data+14))->Flag_Segment;
	((IPHeader_t *)(ICMPBuf+14))->TTL = 64;
	((IPHeader_t *)(ICMPBuf+14))->Protocol = 1;
	((IPHeader_t *)(ICMPBuf+14))->SrcIP = ((IPHeader_t *)(pkt_data+14))->DstIP;
	((IPHeader_t *)(ICMPBuf+14))->DstIP = ((IPHeader_t *)(pkt_data+14))->SrcIP;
	((IPHeader_t *)(ICMPBuf+14))->Checksum = htons(ChecksumCompute((unsigned short *)(ICMPBuf+14),20));

	// 填充ICMP首部
	((ICMPHeader_t *)(ICMPBuf+34))->Type = type;
	((ICMPHeader_t *)(ICMPBuf+34))->Code = code;
	((ICMPHeader_t *)(ICMPBuf+34))->Id = 0;
	((ICMPHeader_t *)(ICMPBuf+34))->Sequence = 0;
	((ICMPHeader_t *)(ICMPBuf+34))->Checksum = htons(ChecksumCompute((unsigned short *)(ICMPBuf+34),8));
	
	// 填充数据
	memcpy((u_char *)(ICMPBuf+42),(IPHeader_t *)(pkt_data+14),20);
	memcpy((u_char *)(ICMPBuf+62),(u_char *)(pkt_data+34),8);

	// 发送数据包
	pcap_sendpacket(pIfInfo->adhandle, (u_char *)ICMPBuf, 70 );
	
	// 日志输出信息
	if (type == 11)
	{
		pDlg->m_Log.InsertString(-1, L"   发送ICMP超时数据包：");
	}
	if (type == 3)
	{
		pDlg->m_Log.InsertString(-1, L"   发送ICMP目的不可达数据包：");
	}
	pDlg->m_Log.InsertString(-1, (L"   ICMP ->" + IPntoa(((IPHeader_t *)(ICMPBuf+14))->DstIP)
		+ L"-" + MACntoa(((FrameHeader_t *)ICMPBuf)->DesMAC)));

	delete [] ICMPBuf;
}

// 判断IP数据包头部校验和是否正确
int IsChecksumRight(char * buffer)
{
	// 获得IP头内容
	IPHeader_t * ip_header = (IPHeader_t *)buffer;  
	// 备份原来的校验和
	unsigned short checksumBuf = ip_header->Checksum;              
	unsigned short check_buff[sizeof(IPHeader_t)];
	// 设IP头中的校验和为0
	ip_header->Checksum = 0;                                       
	
	memset(check_buff, 0, sizeof(IPHeader_t));
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	// 计算IP头部校验和
	ip_header->Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));   

	// 与备份的校验和进行比较
	if (ip_header->Checksum == checksumBuf)                       
	{
		return 1;
	}
	else
	{
		return 0;
	}
}



// 计算校验和
unsigned short ChecksumCompute(unsigned short * buffer,int size)   
{
	// 32位，延迟进位
	unsigned long cksum = 0;                                        
	while (size > 1)
	{
		cksum += * buffer++;
		// 16位相加
		size -= sizeof(unsigned short);                             
	}
	if(size)
	{
		// 最后可能有单独8位
		cksum += *(unsigned char *)buffer;
	}
	// 将高16位进位加至低16位
	cksum = (cksum >> 16) + (cksum & 0xffff);                       
	cksum += (cksum >> 16);
	// 取反
	return (unsigned short)(~cksum);                                
}