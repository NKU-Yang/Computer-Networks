#pragma comment(lib, "Ws2_32.lib")
#include <iostream>
#include <winsock.h>
#include <fstream>
#include<time.h>
#include <string>

using namespace std;
#define PORT 8888

const int MAXLEN = 509;//单个包内最大数据长度
char buffer[200000000];

const unsigned char ACK = 0x01;
const unsigned char NAK = 0x02;
const unsigned char LAST = 0x08;
const unsigned char NOTLAST = 0x18;
const unsigned char SHAKE_1 = 0x03;
const unsigned char SHAKE_2 = 0x04;
const unsigned char SHAKE_3 = 0x05;
const unsigned char WAVE_1 = 0x06;
const unsigned char WAVE_2 = 0x07;
const int MAX_WAIT_TIME = 500;

SOCKET server;
SOCKADDR_IN serverAddr, clientAddr;
//计算校验和
unsigned char checksum(char *package, int len) {
	if (len == 0) {
		return ~(0);
	}
	unsigned int sum = 0;
	int i = 0;
	while (len--) {
		sum += (unsigned char)package[i++];
		if (sum & 0xFF00) {
			sum &= 0x00FF;
			sum++;
		}
	}
	return ~(sum & 0x00FF);
}

void rcv(char *pkt, int &len_recv) {
	char recv[MAXLEN + 4];
	int len_tmp = sizeof(clientAddr);
	int last_order = -1;
	len_recv = 0;
	int count = 0;
	while (true) {
		while (true) {
			memset(recv, 0, sizeof(recv));
			if (recvfrom(server, recv, MAXLEN + 4, 0, (sockaddr *)&clientAddr, &len_tmp) == SOCKET_ERROR)continue;
			char send[3];
			if (checksum(recv, MAXLEN + 4) == 0) {
				if ((unsigned char)recv[2] == unsigned char((last_order + 1) % ((int)UCHAR_MAX + 1))) {
					send[1] = ACK;
					send[2] = recv[2];
					send[0] = checksum(send + 1, 2);
					sendto(server, send, 3, 0, (sockaddr *)&clientAddr, sizeof(clientAddr));
					cout << "已经接受序号为" << count++ << "的包" << endl;
					break;
				}
				//break;
				send[1] = ACK;
				send[2] = recv[2];
				send[0] = checksum(send + 1, 2);
				sendto(server, send, 3, 0, (sockaddr *)&clientAddr, sizeof(clientAddr));
				//cout << "ACK序号为" <<((last_order+1)/256)*256+(int)((unsigned char) recv[2])<< endl;
				continue;
			}
			else {
				send[1] = NAK;
				send[2] = recv[2];
				send[0] = checksum(send + 1, 2);
				sendto(server, send, 3, 0, (sockaddr *)&clientAddr, sizeof(clientAddr));
				printf("NAK\n");
				continue;
			}
		}
		last_order++;
		if (LAST == recv[1]) {
			for (int i = 4; i < recv[3] + 4; i++) {
				pkt[len_recv++] = recv[i];
			}
			break;
		}
		else {
			for (int i = 3; i < MAXLEN + 3; i++) {
				pkt[len_recv++] = recv[i];
			}
		}
	}
}
bool shake_hand() {
	while (true) {
		char recv[2];
		int len_tmp = sizeof(clientAddr);
		while (recvfrom(server, recv, 2, 0, (sockaddr *)&clientAddr, &len_tmp) == SOCKET_ERROR);
		if (checksum(recv, 2) != 0 || recv[1] != SHAKE_1) {
			continue;
		}
		while (true) {
			recv[1] = SHAKE_2;
			recv[0] = checksum(recv + 1, 1);
			sendto(server, recv, 2, 0, (sockaddr *)&clientAddr, sizeof(clientAddr));
			while (recvfrom(server, recv, 2, 0, (sockaddr *)&clientAddr, &len_tmp) == SOCKET_ERROR);
			if (checksum(recv, 2) == 0 && recv[1] == SHAKE_1)
				continue;
			if (checksum(recv, 2) == 0 && recv[1] == SHAKE_3)
				break;
			if (checksum(recv, 2) != 0 || recv[1] != SHAKE_3) {
				printf("error");
				return false;
			}
		}
		break;

	}
	return true;
}
void wave_hand() {
	while (true) {
		char recv[2];
		int len_tmp = sizeof(clientAddr);
		while (recvfrom(server, recv, 2, 0, (sockaddr *)&clientAddr, &len_tmp) == SOCKET_ERROR);
		if (checksum(recv, 2) != 0 || recv[1] != (char)WAVE_1)
			continue;

		recv[1] = WAVE_2;
		recv[0] = checksum(recv + 1, 1);
		sendto(server, recv, 2, 0, (sockaddr *)&clientAddr, sizeof(clientAddr));
		break;
	}
}
int main() {
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata)) {
		printf("error");
		return 0;
	}
	//初始化
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(10005);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	server = socket(AF_INET, SOCK_DGRAM, 0);

	int time_out = 50;//1ms超时
	setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (char *)&time_out, sizeof(time_out));

	if (server == INVALID_SOCKET) {
		printf("socket of server invalid!");
		closesocket(server);
		return 0;
	}
	if (bind(server, (sockaddr *)(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
		printf("bind fail");
		closesocket(server);
		WSACleanup();
		return 0;
	}
	printf("connecting\n");
	//开始握手
	if (!shake_hand()) {
		return 0;
	}
	printf("conect success!\n");
		// 接受文件名
		int len = 0;
		rcv(buffer, len);
		buffer[len] = 0;
		string file_name(buffer);
		cout << file_name << endl;
		if (!strcmp("exit", file_name.c_str())) {
			return 0;
		}
		// 清空缓冲区
		memset(buffer, 0, file_name.length());
		// 接受文件内容
		rcv(buffer, len);
		printf("lenth of file: %d\n", len);
		ofstream out(file_name.c_str(), ofstream::binary);
		for (int i = 0; i < len; i++) {
			out << buffer[i];
		}
		out.close();
		printf("收到文件: %s\n", file_name.c_str());
	
	//挥手
	wave_hand();
	closesocket(server);
	WSACleanup();
	printf("program will close after 3 seconds\n");
	Sleep(3000);
	return 0;
}