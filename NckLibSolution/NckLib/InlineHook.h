#pragma once
#include <Windows.h>
#include "HookBase.h"

//////////////////////////////////////////////////////////
//InlineHook�֧࣬������λ��HOOK
//Author:����ǳ���ü / NCK
//////////////////////////////////////////////////////////
class InlineHook:public HookBase
{
private:
	//һ����hook�����ֽ���
	DWORD dwHookLen;

	//hook�󱻸��ǵ����ֽ�
	BYTE oldBytes[20] = { 0 };

	//��hook�ĵ�ַ
	DWORD dwHookAddress;

	//hook��ת�򵽵ĺ�����ַ
	DWORD dwTargetAddress;

	//hook����ִ����Ϻ󷵻ص��ĵ�ַ
	DWORD dwBackAddress;

	
	//*********************************************************************************************
	// FullName:	����jmp��call��ָ����ֵ,���㹫ʽ��Ŀ���ַ-Դ��ַ-5
	// Returns:		���ؽ�����
	// Parameter:	DWORD dwTargetAddress��Ŀ���ַ
	// Parameter:	DWORD dwSourceAddress��Դ��ַ
	// Author:		����ǳ���ü / NCK
	//*********************************************************************************************
	DWORD CalcJmpCallAddress(DWORD dwTargetAddress, DWORD dwSourceAddress);

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

	
	//*********************************************************************************************
	// FullName:	��ʼHOOK
	// Returns:		HOOK�ɹ�����TRUE��ʧ�ܷ���FALSE
	// Parameter:	DWORD dwSourceAddr: ��HOOK�ĵ�ַ
	// Parameter:	DWORD dwTargetAddr��HOOK����ת���ĵ�ַ
	// Author:		����ǳ���ü / NCK
	//*********************************************************************************************
	BOOL BeginHook(DWORD dwSourceAddr, DWORD dwTargetAddr);

	
	//*********************************************************************************************
	// FullName:	����HOOK���һָ����б�HOOK��Ĺ���
	// Returns:		�ɹ�����TRUEʧ�ܷ���FALSE
	// Author:		����ǳ���ü / NCK
	//*********************************************************************************************
	BOOL EndHook();

	//���ֶ����ڻ�ȡHOOK��Ĵ���������
	InlineHookRegister InlineRegister;

};

