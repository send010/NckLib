#pragma once
#include <Windows.h>
class RemoteThreadInject
{
public:
	RemoteThreadInject();
	~RemoteThreadInject();

	//*********************************************************************************************
	// FullName:	执行远程线程注入
	// Returns:		返回注入后的模块基址
	// Parameter:	DWORD dwProcessId：要注入的进程ID
	// Parameter:	LPTSTR lpszDllName：要注入的模块完整路径
	// Author:		凉游浅笔深画眉 / NCK
	//*********************************************************************************************
	BOOL BeginRemoteThreadInject(DWORD dwProcessId, LPTSTR lpszDllName);
};

