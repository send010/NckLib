#pragma once
#include <Windows.h>
//�ڴ�ע����
class MemoryInject
{
public:
	MemoryInject();
	~MemoryInject();
	//�ڴ�ע��
	//dwPid������ID
	//pInjectBuffer��Ҫע���DLL����
	//dwBufferLen��Ҫע���DLL���ֽ���
	//����ע���ĵ�ַ
	PDWORD BeginInject(DWORD dwPid, LPBYTE pInjectBuffer,DWORD dwBufferLen);

	//�ڴ�ע��
	//dwPid������ID
	//szDllFullPath:Ҫע���DLL����·��
	//����ע���ĵ�ַ
	DWORD BeginInject(DWORD dwPid, PTCHAR szDllFullPath);
};

