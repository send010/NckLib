#pragma once
#include <Windows.h>
//�ڴ�ע����
class MemoryInject
{
public:
	MemoryInject();
	~MemoryInject();

	//*********************************************************************************************
	// FullName:	�ڴ�ע��ģʽһ[����������ע�룬�ù�����δ����]
	// Returns:		����ע��ɹ���Ļ�ַ
	// Parameter:	DWORD dwPid��Ҫע��Ľ���ID
	// Parameter:	LPBYTE pInjectBuffer��Ҫע���ģ�����������
	// Parameter:	DWORD dwBufferLen��Ҫע���ģ����������ݳ���
	// Author:		����ǳ���ü / NCK
	//*********************************************************************************************
	PDWORD BeginInject(DWORD dwPid, LPBYTE pInjectBuffer,DWORD dwBufferLen);


	//*********************************************************************************************
	// FullName:	�ڴ�ע��ģʽ��[DLL·��ע��]
	// Returns:		����ע��ɹ���Ļ�ַ
	// Parameter:	DWORD dwPid��Ҫע��Ľ���ID
	// Parameter:	PTCHAR szDllFullPath��Ҫע���ģ������·��
	// Author:		����ǳ���ü / NCK
	//*********************************************************************************************
	DWORD BeginInject(DWORD dwPid, PTCHAR szDllFullPath);
};

