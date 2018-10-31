#include "InlineHook.h"
#include <stdio.h>
#define BEA_ENGINE_STATIC 
#define BEA_USE_STDCALL
#include "BeaEngine.h"
#include<mmsystem.h>
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"BeaEngine.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(linker,"/nodefaultlib:crt.lib")



InlineHook::InlineHook()
{
}


InlineHook::~InlineHook()
{
	delete this;
}

DWORD InlineHook::CalcJmpAddress(DWORD targetAddress, DWORD hookAddress) 
{
	return targetAddress - hookAddress - 5;
}




BOOL InlineHook::BeginHook(DWORD sourceAddr, DWORD targetAddr)
{
	dwHookAddress = sourceAddr;
	dwTargetAddress = targetAddr;
	//定义反汇编引擎
	DISASM disam;
	memset(&disam, 0, sizeof(DISASM));
	//设置反汇编引擎进行反汇编的位置
	disam.EIP = sourceAddr;
	//执行反汇编
	dwHookLen = Disasm(&disam);
	//当此处字节不够时，继续向下寻找指令，直到大于等于五个字节为止
	while (dwHookLen < 5)
	{
		disam.EIP += dwHookLen;
		dwHookLen += Disasm(&disam);
	}
	//拷贝原始指令
	memcpy_s(oldBytes, dwHookLen, (void*)sourceAddr, dwHookLen);

	//申请一段内存，用来存放ShellCode
	LPBYTE dwShellCodeAddress = (LPBYTE)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


	DWORD regEax = (DWORD)&InlineRegister.EAX;
	DWORD regEcx = (DWORD)&InlineRegister.ECX;
	DWORD regEdx = (DWORD)&InlineRegister.EDX;
	DWORD regEbx = (DWORD)&InlineRegister.EBX;
	DWORD regEsp = (DWORD)&InlineRegister.ESP;
	DWORD regEbp = (DWORD)&InlineRegister.EBP;
	DWORD regEsi = (DWORD)&InlineRegister.ESI;
	DWORD regEdi = (DWORD)&InlineRegister.EDI;

	//定义ShellCode用于执行代码
	BYTE inlineHookShellCode[] =
	{
	  0xA3,0xFF,0xFF,0xFF,0xFF,														//mov dword ptr ds:[0xFFFFFFFF],eax
	  0x89,0x0D,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],ecx
	  0x89,0x15,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],edx
	  0x89,0x1D,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],ebx
	  0x89,0x25,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],esp
	  0x89,0x2D,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],ebp
	  0x89,0x35,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],esi
	  0x89,0x3D,0xFF,0xFF,0xFF,0xFF,												//mov dword ptr ds:[0xFFFFFFFF],edi
	  0x60,																			//pushad
	  0x9C,																			//pushfd
	  0xBB,0xFF,0xFF,0xFF,0xFF,														//mov ebx,0xFFFFFFFF
	  0xFF,0xD3,																	//call ebx
	  0x9D,																			//popfd														
	  0x61,																			//popad
	  0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,   //15个nop
	  0x68,0xFF,0xFF,0xFF,0xFF,														//push 0xFFFFFFFF
	  0xC3																			//retn
	};

	DWORD dwShellCodeAddr = (DWORD)&inlineHookShellCode[0];

	*((LPDWORD)(dwShellCodeAddr + 1)) = regEax;
	*((LPDWORD)(dwShellCodeAddr + 7)) = regEcx;
	*((LPDWORD)(dwShellCodeAddr + 13)) = regEdx;
	*((LPDWORD)(dwShellCodeAddr + 19)) = regEbx;
	*((LPDWORD)(dwShellCodeAddr + 25)) = regEsp;
	*((LPDWORD)(dwShellCodeAddr + 31)) = regEbp;
	*((LPDWORD)(dwShellCodeAddr + 37)) = regEsi;
	*((LPDWORD)(dwShellCodeAddr + 43)) = regEdi;
	*((LPDWORD)(dwShellCodeAddr + 50)) = targetAddr;
	memcpy((LPVOID)(dwShellCodeAddr + 58), (LPVOID)oldBytes, dwHookLen);
	//计算HOOK执行完毕后jmp返回的地址
	dwBackAddress = sourceAddr + dwHookLen;
	*((LPDWORD)(dwShellCodeAddr + 74)) = dwBackAddress;
	//将ShellCode复制到指定内存
	memcpy((LPVOID)dwShellCodeAddress, (LPVOID)inlineHookShellCode, sizeof(inlineHookShellCode) / sizeof(BYTE));
	//修改内存页属性为可读可写可执行
	DWORD oldProtect;
	HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	VirtualProtectEx(hHandle,(LPVOID)sourceAddr, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);

	//这里别用指针操作，加了强壳的程序用指针没用
	CHAR hookBuff[5] = { 0xE9};
	int jmpAddress = CalcJmpAddress((DWORD)dwShellCodeAddress, sourceAddr);
	memcpy(&hookBuff[1], &jmpAddress, 4);
	DWORD dwWriteBytesNum;
	WriteProcessMemory(hHandle, (LPVOID)(sourceAddr), hookBuff,5, &dwWriteBytesNum);
	if (dwWriteBytesNum == 5)
	{
		isHook = true;
		return true;
	}
	else
	{
		return false;
	}
	
}


BOOL InlineHook::EndHook() 
{
	//拷贝原始指令
	memcpy_s((LPVOID)dwHookAddress, dwHookLen, oldBytes, dwHookLen);
	isHook = FALSE;
	return true;
}