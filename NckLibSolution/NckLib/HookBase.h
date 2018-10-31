#pragma once
#include <Windows.h>

class HookBase
{
public:
	HookBase();
	~HookBase();
public:

	//�Ƿ��Ѿ�HOOK
	BOOL isHooked;

	//��ʼHOOK
	virtual BOOL BeginHook(DWORD sourceAddr, DWORD targetAddr)=0;

	//����HOOK���ָ�����HOOK
	virtual BOOL EndHook()=0;
};

