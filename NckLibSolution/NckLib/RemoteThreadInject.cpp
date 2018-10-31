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
	// �򿪽���
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	// ����Զ�̿ռ�
	int cch = 1 + strlen(lpszDllName);
	pszDllFile = (PSTR)VirtualAllocEx(hProcess,
		NULL,
		cch,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (pszDllFile == NULL)
		return FALSE;

	// ��DLL�����ֱ�����ַд�뵽Զ�̿ռ���
	if ((WriteProcessMemory(hProcess,
		(PVOID)pszDllFile,
		(PVOID)lpszDllName,
		cch,
		NULL)) == FALSE)
	{
		return FALSE;
	}

	// ��ȡԶ�̽��̵�ַ�ռ���LoadLibrary�����ĵ�ַ
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
	if (pfnThreadRtn == NULL)
		return FALSE;

	// ����Զ���߳�
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