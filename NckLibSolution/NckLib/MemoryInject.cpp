#include "MemoryInject.h"
#include "MemoryInjectShellCode.h"

DWORD MemoryInject::BeginInject(DWORD dwPid, PTCHAR szDllFullPath)
{
	//打开进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);
	HMODULE pLib = LoadLibrary(szDllFullPath);
	DWORD dwLibBase = (DWORD)pLib;
	//ImageDosHeader
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)dwLibBase;
	//NtHeader
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(dwLibBase + pImageDosHeader->e_lfanew);
	//得到镜像大小
	DWORD imageSize = pImageNtHeader->OptionalHeader.SizeOfImage;
	//申请一段内存用来存放需要注入的DLL数据
	PBYTE realInjectMemory = (PBYTE)VirtualAllocEx(hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//临时用来修复重定位的DLL数据，用完函数结束会释放掉
	PBYTE pTempDll = (PBYTE)VirtualAllocEx(GetCurrentProcess(), NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//复制内存
	RtlMoveMemory(pTempDll, pLib, imageSize);
	
	
	//修正PE指针指向新复制的内存
	dwLibBase = (DWORD)pTempDll;
	pImageDosHeader = (PIMAGE_DOS_HEADER)dwLibBase;
	pImageNtHeader = (PIMAGE_NT_HEADERS)(dwLibBase + pImageDosHeader->e_lfanew);
	//得到重定位表的VA
	PIMAGE_BASE_RELOCATION pRelocVA = (PIMAGE_BASE_RELOCATION)(dwLibBase + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//首先修改ImageBase
	pImageNtHeader->OptionalHeader.ImageBase = (DWORD)realInjectMemory;
	int a = 0;

	while (pRelocVA->SizeOfBlock != 0 && pRelocVA->VirtualAddress != 0)
	{
		//得到当前块需要修复重定位元素的个数
		//块大小-结构体大小得到的是存放数据的还剩多少字节
		//每两个字节(16位)代表一个需要修复的项，所以除以2表示有多少个16位。
		DWORD dwNumberOfFix = (pRelocVA->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION)) / 2;
		//定位到第一个需要修复的元素地址
		PSHORT pFistFix = (PSHORT)((DWORD)pRelocVA + sizeof(IMAGE_BASE_RELOCATION));
		//遍历所有要修复的项并修复
		for (DWORD i = 0; i < dwNumberOfFix; i++)
		{
			SHORT shorFixValue = pFistFix[i];
			//判断高4位是否为3，如果是就代表需要修改
			if (shorFixValue & 0x3000 != 0x3000) continue;
			//得到当前值的低12位，因为高4位是判断是否需要修复，剩下的低12位才是实际需要修复的值
			shorFixValue = shorFixValue & 0xFFF;
			//原始的VA，这里的值是需要修复的
			PDWORD dwWillFix = (PDWORD)((DWORD)pLib + pRelocVA->VirtualAddress + shorFixValue);
			//读取原始的值
			DWORD oldValue = *dwWillFix;
			//原始的值-原始的ImageBase=原始值的RVA
			//原始值的RVA+新的imagebase=新的要写入的值
			DWORD newValue = oldValue - (DWORD)pLib + (DWORD)realInjectMemory;

			//计算新的要写入的地址
			PDWORD dwNewFixAddress = (PDWORD)((DWORD)dwLibBase + pRelocVA->VirtualAddress + shorFixValue);
			//最终修正重定位
			*dwNewFixAddress = newValue;
		}
		//指向下一个重定位块
		pRelocVA = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocVA + pRelocVA->SizeOfBlock);
	}
	DWORD dwOutWriteBytesNum = 0;
	WriteProcessMemory(hProcess, realInjectMemory, pTempDll, imageSize, &dwOutWriteBytesNum);
	//复制完成之后卸载原来的DLL
	FreeLibrary(pLib);
	VirtualFreeEx(hProcess, pTempDll, imageSize, MEM_DECOMMIT);
	return (DWORD)realInjectMemory;
}

PDWORD MemoryInject::BeginInject(DWORD dwPid, LPBYTE injectBuffer, DWORD dwBufferLen)
{
	//--------------------------------------------执行内存注入--------------------------------
	//打开进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);

	//跨进程申请内存
	LPBYTE lpbPeAddress = (LPBYTE)VirtualAllocEx(hProcess, NULL, dwBufferLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	SIZE_T sztWriteNum;
	//写内存字节集
	WriteProcessMemory(hProcess, (LPVOID)lpbPeAddress, injectBuffer, dwBufferLen, &sztWriteNum);

	DWORD shellCodeSize = sizeof(memoryInjectShellCode) / sizeof(BYTE);

	//跨进程申请内存
	LPBYTE lpbShellCodeAddress = (LPBYTE)VirtualAllocEx(hProcess, NULL, shellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	//写内存字节集
	WriteProcessMemory(hProcess, (LPVOID)lpbShellCodeAddress, memoryInjectShellCode, shellCodeSize, &sztWriteNum);


	

	LPBYTE GetAddr = (LPBYTE)((DWORD)lpbShellCodeAddress + 2143);
	LPBYTE FreeAddr = (LPBYTE)((DWORD)GetAddr + 277);

	DWORD threadId;
	HANDLE hThead;
	hThead = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpbShellCodeAddress, lpbPeAddress, 0, &threadId);
	WaitForSingleObject(hThead, -1);
	CloseHandle(hThead);

	//测试写出的文件是否正确
	//FILE* stream;
	//errno_t err;
	//err  = fopen_s(&stream,"demo.exe", "wb");
	//fwrite(pBuffer, dwSize, 1, stream);
	//fclose(stream);
	

	return (LPDWORD)lpbPeAddress;
}

MemoryInject::MemoryInject()
{
}


MemoryInject::~MemoryInject()
{
}
