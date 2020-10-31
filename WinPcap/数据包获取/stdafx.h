// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include<tchar.h>
//the macro HAVE_REMOTE must define before
#ifndef  HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <pcap.h>
#include <remote-ext.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
using namespace std;


// TODO:  在此处引用程序需要的其他头文件
