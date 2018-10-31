#pragma once
#include <Windows.h>
//内存注入类
class MemoryInject
{
public:
	MemoryInject();
	~MemoryInject();

	//*********************************************************************************************
	// FullName:	内存注入模式一[二进制数据注入，该功能尚未完善]
	// Returns:		返回注入成功后的基址
	// Parameter:	DWORD dwPid：要注入的进程ID
	// Parameter:	LPBYTE pInjectBuffer：要注入的模块二进制数据
	// Parameter:	DWORD dwBufferLen：要注入的模块二进制数据长度
	// Author:		凉游浅笔深画眉 / NCK
	//*********************************************************************************************
	PDWORD BeginInject(DWORD dwPid, LPBYTE pInjectBuffer,DWORD dwBufferLen);


	//*********************************************************************************************
	// FullName:	内存注入模式二[DLL路径注入]
	// Returns:		返回注入成功后的基址
	// Parameter:	DWORD dwPid：要注入的进程ID
	// Parameter:	PTCHAR szDllFullPath：要注入的模块完整路径
	// Author:		凉游浅笔深画眉 / NCK
	//*********************************************************************************************
	DWORD BeginInject(DWORD dwPid, PTCHAR szDllFullPath);
};

