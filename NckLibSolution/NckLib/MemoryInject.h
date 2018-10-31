#pragma once
#include <Windows.h>
//内存注入类
class MemoryInject
{
public:
	MemoryInject();
	~MemoryInject();
	//内存注入
	//dwPid：进程ID
	//pInjectBuffer：要注入的DLL数据
	//dwBufferLen：要注入的DLL总字节数
	//返回注入后的地址
	PDWORD BeginInject(DWORD dwPid, LPBYTE pInjectBuffer,DWORD dwBufferLen);

	//内存注入
	//dwPid：进程ID
	//szDllFullPath:要注入的DLL完整路径
	//返回注入后的地址
	DWORD BeginInject(DWORD dwPid, PTCHAR szDllFullPath);
};

