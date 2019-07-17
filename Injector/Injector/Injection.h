#pragma once

#include "Start Routine.h"
#include <fstream>
#include <Psapi.h>

enum INJECTION_MODE
{
	IM_LoadLibrary,
	IM_LdrLoadDll,
	IM_ManualMap
};

#define INJ_ERASE_HEADER				0x0001
#define INJ_FAKE_HEADER					0x0002
#define INJ_UNLINK_FROM_PEB				0x0004
#define INJ_SHIFT_MODULE				0x0008
#define INJ_CLEAN_DATA_DIR				0x0010
#define INJ_HIDE_THREAD_FROM_DEBUGGER	0x0020
#define INJ_SCRAMBLE_DLL_NAME			0x0040
#define INJ_LOAD_DLL_COPY				0x0080
#define INJ_HIHJACK_HANDLE				0x0100 //ignored

#define INJ_MAX_FLAGS 0xFF

DWORD InjectDLL(const char * szDllFile, HANDLE hProc, INJECTION_MODE Mode, LAUNCH_METHOD Method = LM_NtCreateThreadEx, DWORD Flags = 0, DWORD * ErrorCode = nullptr);

#define INJ_ERR_SUCCESS					0x00000000
#define INJ_ERR_INVALID_PROC_HANDLE		0x00000001
#define INJ_ERR_FILE_DOESNT_EXIST		0x00000002
#define INJ_ERR_OUT_OF_MEMORY			0x00000003
#define INJ_ERR_INVALID_DLL_FILE		0x00000004
#define INJ_ERR_IMAGE_CANT_RELOC		0x00000007
#define INJ_ERR_LDRLOADDLL_MISSING		0x00000009
#define INJ_ERR_REMOTEFUNC_MISSING		0x0000000A
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
#define INJ_ERR_INVALID_TARGET_ARCH		0x8000000D

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

#define ALIGN_UP(X, A) (X + (A - 1)) & (~(A - 1))
#define ALIGN_IMAGE_BASE_X64(Base) ALIGN_UP(Base, 0x10)
#define ALIGN_IMAGE_BASE_X86(Base) ALIGN_UP(Base, 0x08)
#ifdef _WIN64 
#define ALIGN_IMAGE_BASE(Base) ALIGN_IMAGE_BASE_X64(Base)
#else
#define ALIGN_IMAGE_BASE(Base) ALIGN_IMAGE_BASE_X86(Base)
#endif

using f_LoadLibraryA		= decltype(LoadLibraryA);
using f_GetProcAddress		= UINT_PTR	(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT		= BOOL		(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);
using f_VirtualAlloc		= decltype(VirtualAlloc);
using f_VirtualFree			= decltype(VirtualFree);

struct LOAD_LIBRARY_DATA
{	
	HINSTANCE			hRet;
	f_LoadLibraryA *	pLoadLibraryA;
	char				szDll[MAX_PATH];
};

struct LDR_LOAD_DLL_DATA
{
	HANDLE			hRet;
	f_LdrLoadDll	pLdrLoadDll;
	UNICODE_STRING	pModuleFileName;
	BYTE			Data[MAX_PATH * 2];
};

struct MANUAL_MAPPING_DATA
{
	HINSTANCE			hRet;
	f_LoadLibraryA *	pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	f_VirtualAlloc *	pVirtualAlloc;
	f_VirtualFree *		pVirtualFree;
	BYTE *				pModuleBase;
	DWORD				Flags;
};