#include "Common.h"

DWORD Bin_Search(BYTE * pSourceArrary, DWORD dwSourceLen, BYTE *pTargetArray, DWORD dwTargetLen)
{
	for (int i = 0; i <= dwSourceLen - dwTargetLen; i++)
	{
		if (pSourceArrary[i] == pTargetArray[0])
		{
			BOOL isFind = TRUE;
			for (int j = 0; j < dwTargetLen; j++)
			{
				if (pSourceArrary[i + j] != pTargetArray[j])
				{
					isFind = FALSE;
					break;
				}
			}
			if (isFind)
			{
				return i;
			}
		}
	}
	return 0;
}



int Str_IsEndWith(const char *str1, char *str2)
{
	if (str1 == NULL || str2 == NULL)
		return -1;
	int len1 = strlen(str1);
	int len2 = strlen(str2);
	if ((len1 < len2) || (len1 == 0 || len2 == 0))
		return -1;
	while (len2 >= 1)
	{
		if (str2[len2 - 1] != str1[len1 - 1])
			return 0;
		len2--;
		len1--;
	}
	return 1;
}