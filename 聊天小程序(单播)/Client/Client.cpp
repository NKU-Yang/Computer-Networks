// Client.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<iostream>
#include<cstdio>
#include<string>
#include<Winsock2.h>
#pragma comment(lib,"ws2_32.lib")
using namespace std;
const int PORT = 8000;
#define MaxBufSize 1024
#define _CRT_SECURE_NO_WARINGS

int _tmain(int argc, _TCHAR* argv[])
{
	WSADATA wsd;
	WSAStartup(MAKEWORD(2, 2), &wsd);
	SOCKET SocketClient = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN ClientAddr;
	ClientAddr.sin_family = AF_INET;
	ClientAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	ClientAddr.sin_port = htons(PORT);
	int n = 0;
	n = connect(SocketClient, (struct sockaddr*)&ClientAddr, sizeof(ClientAddr));
	if (n == SOCKET_ERROR)
	{
		cout << "failed to connect" << endl;
		return -1;
	}
	cout << "success to connect to Server" << endl;
	
	char info[1024];
	char SendBuff[MaxBufSize];
	char RecvBuff[MaxBufSize];
	while (1)
	{
		cout << "input your message:" << endl;
		scanf_s("%s",&info,MaxBufSize);
		//gets(info);
		if (info[0] == '\0')
			break;
		strcpy(SendBuff, info);
		memset(info, 0, sizeof(info));
		int k = 0;
		k = send(SocketClient, SendBuff, sizeof(SendBuff), 0);
		memset(SendBuff, 0, sizeof(SendBuff));
		if (k < 0)
		{
			cout << WSAGetLastError() << endl;
			cout << "failed to send" << endl;
		}
		int n = 0;
		n = recv(SocketClient, RecvBuff, sizeof(RecvBuff), 0);
		if (n>0)
		{
			cout << "receive message from Server:" << RecvBuff << endl;
			memset(RecvBuff, 0, sizeof(RecvBuff));
		}
	}
	closesocket(SocketClient);
	WSACleanup();
	return 0;
}

