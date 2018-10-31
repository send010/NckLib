#pragma once
#include <Windows.h>

class HookBase
{
public:
	HookBase();
	~HookBase();
public:

	//是否已经HOOK
	BOOL isHooked;

	//开始HOOK
	virtual BOOL BeginHook(DWORD sourceAddr, DWORD targetAddr)=0;

	//结束HOOK并恢复所有HOOK
	virtual BOOL EndHook()=0;
};

