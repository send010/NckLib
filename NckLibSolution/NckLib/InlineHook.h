#pragma once
#include <Windows.h>
#include "HookBase.h"

//////////////////////////////////////////////////////////
//InlineHook类，支持任意位置HOOK
//Author:凉游浅笔深画眉 / NCK
//////////////////////////////////////////////////////////
class InlineHook:public HookBase
{
private:
	//一共被hook掉的字节数
	DWORD dwHookLen;

	//hook后被覆盖掉的字节
	BYTE oldBytes[20] = { 0 };

	//被hook的地址
	DWORD dwHookAddress;

	//hook后转向到的函数地址
	DWORD dwTargetAddress;

	//hook代码执行完毕后返回到的地址
	DWORD dwBackAddress;

	
	//*********************************************************************************************
	// FullName:	计算jmp、call等指令后的值,计算公式：目标地址-源地址-5
	// Returns:		返回结算结果
	// Parameter:	DWORD dwTargetAddress：目标地址
	// Parameter:	DWORD dwSourceAddress：源地址
	// Author:		凉游浅笔深画眉 / NCK
	//*********************************************************************************************
	DWORD CalcJmpCallAddress(DWORD dwTargetAddress, DWORD dwSourceAddress);

public:
	//Hook后存放数据
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
	 //构造函数
	InlineHook();

	//析构函数
	virtual ~InlineHook();

	
	//*********************************************************************************************
	// FullName:	开始HOOK
	// Returns:		HOOK成功返回TRUE，失败返回FALSE
	// Parameter:	DWORD dwSourceAddr: 被HOOK的地址
	// Parameter:	DWORD dwTargetAddr：HOOK后跳转到的地址
	// Author:		凉游浅笔深画眉 / NCK
	//*********************************************************************************************
	BOOL BeginHook(DWORD dwSourceAddr, DWORD dwTargetAddr);

	
	//*********************************************************************************************
	// FullName:	结束HOOK并且恢复所有被HOOK后的钩子
	// Returns:		成功返回TRUE失败返回FALSE
	// Author:		凉游浅笔深画眉 / NCK
	//*********************************************************************************************
	BOOL EndHook();

	//该字段用于获取HOOK后寄存器的数据
	InlineHookRegister InlineRegister;

};

