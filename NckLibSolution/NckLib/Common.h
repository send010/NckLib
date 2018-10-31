#pragma once
#include <Windows.h>

///////////=====================================二进制相关=================================////////////////////


//*********************************************************************************************
// FullName:  特征码搜索，不支持模糊搜索
// Returns:   特征码所在偏移
// Parameter: BYTE * pSourceArrary：被搜索的二进制数组
// Parameter: DWORD dwSourceLen：被搜索的二进制数组长度
// Parameter: BYTE * pTargetArray：特征码数组
// Parameter: DWORD dwTargetLen：特征码数组长度
// Author:    凉游浅笔深画眉 / NCK
//*********************************************************************************************
DWORD Bin_Search(BYTE * pSourceArrary, DWORD dwSourceLen, BYTE *pTargetArray, DWORD dwTargetLen);







///////////=====================================字符串相关=================================////////////////////

//*********************************************************************************************
// FullName:  判断字符串str1，是否以str2结束
// Returns:   int：如果是则返回1，不是返回0，出错返回-1
// Parameter: const char * str1：字符串1
// Parameter: char * str2：字符串2
// Author:    凉游浅笔深画眉 / NCK
//*********************************************************************************************
int Str_IsEndWith(const char *str1, char *str2);

