#pragma once
#include <Windows.h>
class RemoteThreadInject
{
public:
	RemoteThreadInject();
	~RemoteThreadInject();
	DWORD DoRemoteThreadInject(DWORD dwProcessId, LPTSTR lpszDllName);
};

