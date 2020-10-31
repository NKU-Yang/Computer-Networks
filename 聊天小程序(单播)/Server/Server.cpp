// 聊天室.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<WinSock2.h>
#include<string.h>
#include<iostream>
#pragma comment (lib, "ws2_32.lib")
using namespace std;
const int PORT = 8000;
#define IP "127.0.0.1"
#define MaxClient 10
#define MaxBufSize 1024
int num =0;//客户端数量
#define _CRT_SECURE_NO_WARINGS

//服务线程
DWORD WINAPI SeverThread(LPVOID lpParameter)
{
	SOCKET *ClientSocket = (SOCKET*)lpParameter;
	int receByt = 0;
	char RecvBuf[MaxBufSize];
	char SendBuf[MaxBufSize];
	char exitBuf[5];
	while (1)
	{
		receByt = recv(*ClientSocket, RecvBuf, sizeof(RecvBuf), 0);
		if (receByt > 0)
		{
			if (strlen(RecvBuf)==4)
			{
				for (int i = 0; i < 5; i++)
				{
					exitBuf[i] = RecvBuf[i];
				}
				int flag = strcmp(exitBuf, "exit");
				if (flag==0)//接收到exit消息
				{
					cout << "client " << *ClientSocket << " exit!" << endl;
					num--;
					send(*ClientSocket, "Your server has been closed", sizeof(SendBuf), 0);
					closesocket(*ClientSocket);
					return 0;
				}
			}
				cout << "receive message :" << RecvBuf << " from client:" << *ClientSocket << endl;
			
		}
		else
		{
			if (WSAGetLastError() == 10054)//检测到客户端主动关闭连接
			{
				cout << "client " << *ClientSocket << " exit!" << endl;
				closesocket(*ClientSocket);
				num--;
				return 0;
			}
			else//接收失败显示错误信息
			{
				cout << "failed to receive,Error:" << WSAGetLastError() << endl;
				break;
			}
			
		}
		memset(RecvBuf, 0, 1024);
		cout << "input your message to client:" << endl;
		scanf_s("%s",SendBuf,MaxBufSize);
		int k = 0;
		k = send(*ClientSocket, SendBuf, sizeof(SendBuf), 0);
		if (k < 0)
		{
			if (WSAGetLastError()==10054)//检测到客户端主动关闭连接
			{
				cout << "client " << *ClientSocket << " exit!" << endl;
				closesocket(*ClientSocket);
				num--;
				return 0;
			}
			else//发送失败显示错误信息
			cout << "failed to send, Error:" << WSAGetLastError()<<endl;
		}
		memset(SendBuf, 0, 1024);
	}
	if (*ClientSocket != INVALID_SOCKET)
	{
		closesocket(*ClientSocket);
	}
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	WSAData wsd;
	WSAStartup(MAKEWORD(2, 2), &wsd);
	SOCKET ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN ListenAddr;
	ListenAddr.sin_family = AF_INET;
	ListenAddr.sin_addr.S_un.S_addr = INADDR_ANY;//本机ip
	ListenAddr.sin_port = htons(PORT);
	//绑定监听端口
	int n;
	n = bind(ListenSocket, (LPSOCKADDR)&ListenAddr, sizeof(ListenAddr));
	if (n == SOCKET_ERROR)
	{
		cout << "failed to bind!" << endl;
		return -1;
	}
	else
	{
		cout << "bind success to:" << PORT << endl;
	}
	//开始监听
	int l = listen(ListenSocket, MaxClient);
	if (l == 0)
	{
		cout << "server ready, wait to requirement..." << endl;
	}
	else
	{
		cout << "Error:" << GetLastError() << "listen return" << l << endl;
	}
	while (1)
	{
		//循环接收客户端连接请求并创建服务线程
		if(num < MaxClient)
		{
			SOCKET *ClientSocket=new SOCKET;
			HANDLE hThread;
			int SockAddrlen = sizeof(sockaddr);
			*ClientSocket = accept(ListenSocket, 0, 0);
			cout << "client " << *ClientSocket << " has connect to server" << endl;
			num++;
			hThread = CreateThread(NULL, NULL, &SeverThread, (LPVOID)ClientSocket, 0, NULL);
			CloseHandle(hThread);
		}
		else
		{
			cout << "Max Client!Please wait for accept..." << endl;
		}
	}
	closesocket(ListenSocket);
	WSACleanup();
	return 0;
}

