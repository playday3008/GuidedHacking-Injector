#pragma once

#include "NT Stuff.h"
#include <TlHelp32.h>
#include <strsafe.h>
#include <tchar.h>
#include <fstream>
#include <Psapi.h>
#include <vector>
#include <ctime>
#include <wtsapi32.h>

#define GH_INJ_VERSION L"3.0"

#define GH_INJ_MOD_NAME64W L"GH Injector - x64.dll"
#define GH_INJ_MOD_NAME86W L"GH Injector - x86.dll"

#define GH_INJ_MOD_NAME64A "GH Injector - x64.dll"
#define GH_INJ_MOD_NAME86A "GH Injector - x86.dll"

#ifdef _WIN64
#define GH_INJ_MOD_NAMEW GH_INJ_MOD_NAME64W
#define GH_INJ_MOD_NAMEA GH_INJ_MOD_NAME64A
#else 
#define GH_INJ_MOD_NAMEW GH_INJ_MOD_NAME86W
#define GH_INJ_MOD_NAMEA GH_INJ_MOD_NAME86A
#endif

extern HINSTANCE g_hInjMod;

UINT __forceinline _strlenA(const char * szString)
{
	UINT Ret = 0;
	for (; *szString++; Ret++);
	return Ret;
}

void __forceinline _ZeroMemory(BYTE * pData, UINT Len)
{
	while (Len--)
		*pData++ = 0;
}

#define INJ_ERR_CANT_OPEN_FILE		0x20000000
#define INJ_ERR_INVALID_FILE_SIZE	0x20000001
#define INJ_ERR_INVALID_FILE		0x20000002

struct ERROR_INFO
{
	const wchar_t *	szDllFileName;
	DWORD			TargetProcessId;
	DWORD			InjectionMode;
	DWORD			LaunchMethod;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			LastWin32Error;
	DWORD			HandleValue;
	bool			bNative;
};

bool	FileExists			(const wchar_t * szFile);
bool	IsNativeProcess		(HANDLE hProc);
ULONG	GetSessionId		(HANDLE hTargetProc, NTSTATUS & ntRetOut);
DWORD	ValidateFile		(const wchar_t * szFile, DWORD desired_machine);
bool	GetOwnModulePath	(wchar_t * pOut, size_t BufferCchSize);
void	ErrorLog			(ERROR_INFO * info);
bool	IsElevatedProcess	(HANDLE hProc);