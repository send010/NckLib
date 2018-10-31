#pragma once
#include <Windows.h>
#include "HookBase.h"
class InlineHook:public HookBase
{
private:
	//һ����hook�����ֽ���
	DWORD dwHookLen;

	//hook�󱻸��ǵ����ֽ�
	BYTE oldBytes[20] = { 0 };

	//ִ��hook�ĵ�ַ
	DWORD dwHookAddress;

	//hook��ĺ�����ַ
	DWORD dwTargetAddress;

	//hook����ִ����Ϻ󷵻ص��ĵ�ַ
	DWORD dwBackAddress;

	//����jmpָ����ֵ,���㹫ʽ��Ŀ���ַ-Դ��ַ-5
	DWORD CalcJmpAddress(DWORD targetAddress, DWORD hookAddress);

public:
	//Hook��������
	 struct InlineHookRegister
	{
		DWORD EAX;
		DWORD ECX;
		DWORD EDX;
		DWORD EBX;
		DWORD ESP;
		DWORD EBP;
		DWORD ESI;
		DWORD EDI;

	};
	 //���캯��
	InlineHook();

	//��������
	virtual ~InlineHook();

	//��ʼHOOK
	BOOL BeginHook(DWORD sourceAddr, DWORD targetAddr);

	//����HOOK���һָ����й���
	BOOL EndHook();

	//���ֶ����ڻ�ȡHOOK��Ĵ���������
	InlineHookRegister InlineRegister;

};

