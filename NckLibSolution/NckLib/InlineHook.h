#pragma once
#include <Windows.h>
#include "HookBase.h"
class InlineHook:public HookBase
{
private:
	//一共被hook掉的字节数
	DWORD dwHookLen;

	//hook后被覆盖掉的字节
	BYTE oldBytes[20] = { 0 };

	//执行hook的地址
	DWORD dwHookAddress;

	//hook后的函数地址
	DWORD dwTargetAddress;

	//hook代码执行完毕后返回到的地址
	DWORD dwBackAddress;

	//计算jmp指令后的值,计算公式：目标地址-源地址-5
	DWORD CalcJmpAddress(DWORD targetAddress, DWORD hookAddress);

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

	//开始HOOK
	BOOL BeginHook(DWORD sourceAddr, DWORD targetAddr);

	//结束HOOK并且恢复所有钩子
	BOOL EndHook();

	//该字段用于获取HOOK后寄存器的数据
	InlineHookRegister InlineRegister;

};

