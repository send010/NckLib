#include "MemoryInject.h"
#include "MemoryInjectShellCode.h"

DWORD MemoryInject::BeginInject(DWORD dwPid, PTCHAR szDllFullPath)
{
	//�򿪽���
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);
	HMODULE pLib = LoadLibrary(szDllFullPath);
	DWORD dwLibBase = (DWORD)pLib;
	//ImageDosHeader
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)dwLibBase;
	//NtHeader
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(dwLibBase + pImageDosHeader->e_lfanew);
	//�õ������С
	DWORD imageSize = pImageNtHeader->OptionalHeader.SizeOfImage;
	//����һ���ڴ����������Ҫע���DLL����
	PBYTE realInjectMemory = (PBYTE)VirtualAllocEx(hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//��ʱ�����޸��ض�λ��DLL���ݣ����꺯���������ͷŵ�
	PBYTE pTempDll = (PBYTE)VirtualAllocEx(GetCurrentProcess(), NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//�����ڴ�
	RtlMoveMemory(pTempDll, pLib, imageSize);
	
	
	//����PEָ��ָ���¸��Ƶ��ڴ�
	dwLibBase = (DWORD)pTempDll;
	pImageDosHeader = (PIMAGE_DOS_HEADER)dwLibBase;
	pImageNtHeader = (PIMAGE_NT_HEADERS)(dwLibBase + pImageDosHeader->e_lfanew);
	//�õ��ض�λ���VA
	PIMAGE_BASE_RELOCATION pRelocVA = (PIMAGE_BASE_RELOCATION)(dwLibBase + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//�����޸�ImageBase
	pImageNtHeader->OptionalHeader.ImageBase = (DWORD)realInjectMemory;
	int a = 0;

	while (pRelocVA->SizeOfBlock != 0 && pRelocVA->VirtualAddress != 0)
	{
		//�õ���ǰ����Ҫ�޸��ض�λԪ�صĸ���
		//���С-�ṹ���С�õ����Ǵ�����ݵĻ�ʣ�����ֽ�
		//ÿ�����ֽ�(16λ)����һ����Ҫ�޸�������Գ���2��ʾ�ж��ٸ�16λ��
		DWORD dwNumberOfFix = (pRelocVA->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION)) / 2;
		//��λ����һ����Ҫ�޸���Ԫ�ص�ַ
		PSHORT pFistFix = (PSHORT)((DWORD)pRelocVA + sizeof(IMAGE_BASE_RELOCATION));
		//��������Ҫ�޸�����޸�
		for (DWORD i = 0; i < dwNumberOfFix; i++)
		{
			SHORT shorFixValue = pFistFix[i];
			//�жϸ�4λ�Ƿ�Ϊ3������Ǿʹ�����Ҫ�޸�
			if (shorFixValue & 0x3000 != 0x3000) continue;
			//�õ���ǰֵ�ĵ�12λ����Ϊ��4λ���ж��Ƿ���Ҫ�޸���ʣ�µĵ�12λ����ʵ����Ҫ�޸���ֵ
			shorFixValue = shorFixValue & 0xFFF;
			//ԭʼ��VA�������ֵ����Ҫ�޸���
			PDWORD dwWillFix = (PDWORD)((DWORD)pLib + pRelocVA->VirtualAddress + shorFixValue);
			//��ȡԭʼ��ֵ
			DWORD oldValue = *dwWillFix;
			//ԭʼ��ֵ-ԭʼ��ImageBase=ԭʼֵ��RVA
			//ԭʼֵ��RVA+�µ�imagebase=�µ�Ҫд���ֵ
			DWORD newValue = oldValue - (DWORD)pLib + (DWORD)realInjectMemory;

			//�����µ�Ҫд��ĵ�ַ
			PDWORD dwNewFixAddress = (PDWORD)((DWORD)dwLibBase + pRelocVA->VirtualAddress + shorFixValue);
			//���������ض�λ
			*dwNewFixAddress = newValue;
		}
		//ָ����һ���ض�λ��
		pRelocVA = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocVA + pRelocVA->SizeOfBlock);
	}
	DWORD dwOutWriteBytesNum = 0;
	WriteProcessMemory(hProcess, realInjectMemory, pTempDll, imageSize, &dwOutWriteBytesNum);
	//�������֮��ж��ԭ����DLL
	FreeLibrary(pLib);
	VirtualFreeEx(hProcess, pTempDll, imageSize, MEM_DECOMMIT);
	return (DWORD)realInjectMemory;
}

PDWORD MemoryInject::BeginInject(DWORD dwPid, LPBYTE injectBuffer, DWORD dwBufferLen)
{
	//--------------------------------------------ִ���ڴ�ע��--------------------------------
	//�򿪽���
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);

	//����������ڴ�
	LPBYTE lpbPeAddress = (LPBYTE)VirtualAllocEx(hProcess, NULL, dwBufferLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	SIZE_T sztWriteNum;
	//д�ڴ��ֽڼ�
	WriteProcessMemory(hProcess, (LPVOID)lpbPeAddress, injectBuffer, dwBufferLen, &sztWriteNum);

	DWORD shellCodeSize = sizeof(memoryInjectShellCode) / sizeof(BYTE);

	//����������ڴ�
	LPBYTE lpbShellCodeAddress = (LPBYTE)VirtualAllocEx(hProcess, NULL, shellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	//д�ڴ��ֽڼ�
	WriteProcessMemory(hProcess, (LPVOID)lpbShellCodeAddress, memoryInjectShellCode, shellCodeSize, &sztWriteNum);


	

	LPBYTE GetAddr = (LPBYTE)((DWORD)lpbShellCodeAddress + 2143);
	LPBYTE FreeAddr = (LPBYTE)((DWORD)GetAddr + 277);

	DWORD threadId;
	HANDLE hThead;
	hThead = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpbShellCodeAddress, lpbPeAddress, 0, &threadId);
	WaitForSingleObject(hThead, -1);
	CloseHandle(hThead);

	//����д�����ļ��Ƿ���ȷ
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
