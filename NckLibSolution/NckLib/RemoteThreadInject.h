#pragma once
#include <Windows.h>
class RemoteThreadInject
{
public:
	RemoteThreadInject();
	~RemoteThreadInject();

	//*********************************************************************************************
	// FullName:	ִ��Զ���߳�ע��
	// Returns:		����ע����ģ���ַ
	// Parameter:	DWORD dwProcessId��Ҫע��Ľ���ID
	// Parameter:	LPTSTR lpszDllName��Ҫע���ģ������·��
	// Author:		����ǳ���ü / NCK
	//*********************************************************************************************
	BOOL BeginRemoteThreadInject(DWORD dwProcessId, LPTSTR lpszDllName);
};

