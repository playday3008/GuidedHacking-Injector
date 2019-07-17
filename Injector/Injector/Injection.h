#pragma once

#ifndef INJECTION_H
#define INJECTION_H

#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>
#include <Psapi.h>
#include "NT Stuff.h"
#include "Tools.h"
#include "Import Handler.h"

enum INJECTION_MODE
{
	IM_LoadLibrary,
	IM_LdrLoadDll,
	IM_ManualMap
};

enum LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_UserAPC
};

#define INJ_ERASE_HEADER				0x01
#define INJ_FAKE_HEADER					0x02
#define INJ_UNLINK_FROM_PEB				0x04
#define INJ_SHIFT_MODULE				0x08
#define INJ_CLEAN_DATA_DIR				0x10
#define INJ_HIDE_THREAD_FROM_DEBUGGER	0x20

#define INJ_MAX_FLAGS 0x3F

DWORD InjectDLL(const char * szDllFile, HANDLE hProc, INJECTION_MODE Mode, LAUNCH_METHOD Method = LM_NtCreateThreadEx, DWORD Flags = 0, DWORD * ErrorCode = nullptr);

#define INJ_ERR_SUCCESS					0x00000000
#define INJ_ERR_INVALID_PROC_HANDLE		0x00000001
#define INJ_ERR_FILE_DOESNT_EXIST		0x00000002
#define INJ_ERR_OUT_OF_MEMORY			0x00000003
#define INJ_ERR_INVALID_FILE			0x00000004
#define INJ_ERR_NO_X64FILE				0x00000005
#define INJ_ERR_NO_X86FILE				0x00000006
#define INJ_ERR_IMAGE_CANT_RELOC		0x00000007
#define INJ_ERR_NTDLL_MISSING			0x00000008
#define INJ_ERR_LDRLOADDLL_MISSING		0x00000009
#define INJ_ERR_LOADLIBRARY_MISSING		0x0000000A
#define INJ_ERR_INVALID_FLAGS			0x0000000B
#define INJ_ERR_CANT_FIND_MOD			0x0000000C
#define INJ_ERR_CANT_FIND_MOD_PEB		0x0000000D

#define INJ_ERR_UNKNOWN					0x80000000
#define INJ_ERR_CANT_CREATE_THREAD		0x80000001
#define INJ_ERR_CANT_ALLOC_MEM			0x80000002
#define INJ_ERR_WPM_FAIL				0x80000003
#define INJ_ERR_TH32_FAIL				0x80000004
#define INJ_ERR_CANT_GET_PEB			0x80000005
#define INJ_ERR_CANT_ACCESS_PEB			0x80000006
#define INJ_ERR_CANT_ACCESS_PEB_LDR		0x80000007
#define INJ_ERR_CHECK_WIN32_ERROR		0x80000008
#define INJ_ERR_VPE_FAIL				0x80000009
#define INJ_ERR_INVALID_ARGC			0x8000000A
#define INJ_ERR_SET_PRIV_FAIL			0x8000000B
#define INJ_ERR_CANT_OPEN_PROCESS		0x8000000C
#define INJ_ERR_CANT_START_X64_INJ		0x8000000D
#define INJ_ERR_INVALID_PID				0x8000000E

#define INJ_ERR_ADV_UNKNOWN				0x00000000
#define INJ_ERR_ADV_INV_PROC			0x00000001
#define INJ_ERR_ADV_TH32_FAIL			0x00000002
#define INJ_ERR_ADV_NO_THREADS			0x00000003
#define INJ_ERR_ADV_CANT_OPEN_THREAD	0x00000004
#define INJ_ERR_ADV_SUSPEND_FAIL		0x00000005
#define INJ_ERR_ADV_GET_CONTEXT_FAIL	0x00000006
#define INJ_ERR_ADV_OUT_OF_MEMORY		0x00000007
#define INJ_ERR_ADV_WPM_FAIL			0x00000008
#define INJ_ERR_ADV_SET_CONTEXT_FAIL	0x00000009
#define INJ_ERR_ADV_RESUME_FAIL			0x0000000A
#define INJ_ERR_ADV_QIP_MISSING			0x0000000B
#define INJ_ERR_ADV_QIP_FAIL			0x0000000C
#define INJ_ERR_ADV_CANT_FIND_MODULE	0x0000000D
#define INJ_ERR_ADV_NO_WIN_THREAD		0x0000000E
#define INJ_ERR_ADV_NO_APC_THREAD		0x0000000F

#ifdef ReCa
#undef ReCa
#endif
#define ReCa reinterpret_cast

#ifdef UNICODE
#undef Module32First
#undef Module32Next
#undef MODULEENTRY32
#endif

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
	#define RELOC_FLAG RELOC_FLAG64
#else
	#define RELOC_FLAG RELOC_FLAG32
#endif

using f_LoadLibraryA		= HINSTANCE	(WINAPI*)(const char * lpLibFileName);
using f_GetProcAddress		= UINT_PTR	(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT		= BOOL		(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);
using f_CallNextHookEx		= LRESULT	(WINAPI*)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
using f_RemoteFunc			= void		(__stdcall*)(void * pArg);

struct LOAD_LIBRARY_DATA
{	
	f_LoadLibraryA	pLoadLibraryA;
	char			szDll[MAX_PATH];
};

struct LDR_LOAD_DLL_DATA
{
	f_LdrLoadDll	pLdrLoadDll;
	HANDLE			Out;
	UNICODE_STRING	pModuleFileName;
	BYTE			Data[MAX_PATH * 2];
};

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	DWORD				Flags;
};

#endif