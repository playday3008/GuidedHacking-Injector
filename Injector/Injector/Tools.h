#pragma once

#ifndef TOOLS_H
#define TOOLS_H

#include <Windows.h>
#include "NT Stuff.h"

UINT __forceinline _strlenA(const char * szString)
{
	UINT Ret = 0;
	for (; *szString++; Ret++);
	return Ret;
}

void __forceinline _ZeroMemory(BYTE * pMem, UINT Size)
{
	for (BYTE * i = pMem; i < pMem + Size; ++i)
		*i = 0x00;
}

bool __forceinline FileExistsA(const char * szFile)
{
	return (GetFileAttributesA(szFile) != INVALID_FILE_ATTRIBUTES);
}

#endif