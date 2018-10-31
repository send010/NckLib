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
	//���巴�������
	DISASM disam;
	memset(&disam, 0, sizeof(DISASM));
	//���÷����������з�����λ��
	disam.EIP = sourceAddr;
	//ִ�з����
	dwHookLen = Disasm(&disam);
	//���˴��ֽڲ���ʱ����������Ѱ��ָ�ֱ�����ڵ�������ֽ�Ϊֹ
	while (dwHookLen < 5)
	{
		disam.EIP += dwHookLen;
		dwHookLen += Disasm(&disam);
	}
	//����ԭʼָ��
	memcpy_s(oldBytes, dwHookLen, (void*)sourceAddr, dwHookLen);

	//����һ���ڴ棬�������ShellCode
	LPBYTE dwShellCodeAddress = (LPBYTE)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


	DWORD regEax = (DWORD)&InlineRegister.EAX;
	DWORD regEcx = (DWORD)&InlineRegister.ECX;
	DWORD regEdx = (DWORD)&InlineRegister.EDX;
	DWORD regEbx = (DWORD)&InlineRegister.EBX;
	DWORD regEsp = (DWORD)&InlineRegister.ESP;
	DWORD regEbp = (DWORD)&InlineRegister.EBP;
	DWORD regEsi = (DWORD)&InlineRegister.ESI;
	DWORD regEdi = (DWORD)&InlineRegister.EDI;

	//����ShellCode����ִ�д���
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
	  0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,   //15��nop
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
	//����HOOKִ����Ϻ�jmp���صĵ�ַ
	dwBackAddress = sourceAddr + dwHookLen;
	*((LPDWORD)(dwShellCodeAddr + 74)) = dwBackAddress;
	//��ShellCode���Ƶ�ָ���ڴ�
	memcpy((LPVOID)dwShellCodeAddress, (LPVOID)inlineHookShellCode, sizeof(inlineHookShellCode) / sizeof(BYTE));
	//�޸��ڴ�ҳ����Ϊ�ɶ���д��ִ��
	DWORD oldProtect;
	HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	VirtualProtectEx(hHandle,(LPVOID)sourceAddr, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);

	//�������ָ�����������ǿ�ǵĳ�����ָ��û��
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
	//����ԭʼָ��
	memcpy_s((LPVOID)dwHookAddress, dwHookLen, oldBytes, dwHookLen);
	isHook = FALSE;
	return true;
}