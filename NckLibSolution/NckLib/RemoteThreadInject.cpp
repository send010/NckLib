#include "RemoteThreadInject.h"



RemoteThreadInject::RemoteThreadInject()
{
}


RemoteThreadInject::~RemoteThreadInject()
{
}
DWORD RemoteThreadInject::DoRemoteThreadInject(DWORD dwProcessId, LPTSTR lpszDllName)
{
	HANDLE	hProcess = NULL;
	HANDLE	hThread = NULL;
	PSTR		pszDllFile = NULL;
	// 打开进程
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	// 分配远程空间
	int cch = 1 + strlen(lpszDllName);
	pszDllFile = (PSTR)VirtualAllocEx(hProcess,
		NULL,
		cch,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (pszDllFile == NULL)
		return FALSE;

	// 把DLL的名字变量地址写入到远程空间中
	if ((WriteProcessMemory(hProcess,
		(PVOID)pszDllFile,
		(PVOID)lpszDllName,
		cch,
		NULL)) == FALSE)
	{
		return FALSE;
	}

	// 获取远程进程地址空间中LoadLibrary函数的地址
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
	if (pfnThreadRtn == NULL)
		return FALSE;

	// 创建远程线程
	hThread = CreateRemoteThread(hProcess,
		NULL,
		0,
		pfnThreadRtn,
		(PVOID)pszDllFile,
		0,
		NULL);
	if (hThread == NULL)
		return FALSE;
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, (PVOID)pszDllFile, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return (DWORD)GetModuleHandle(lpszDllName);
}