#pragma once

#include "Eject.h"
#include "Handle Hijacking.h"

#define EXPORT_FUNCTION(export_name, link_name) comment(linker, "/EXPORT:" export_name "=" link_name)

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
#define INJ_THREAD_CREATE_CLOAKED		0x0020
#define INJ_SCRAMBLE_DLL_NAME			0x0040
#define INJ_LOAD_DLL_COPY				0x0080
#define INJ_HIJACK_HANDLE				0x0100
#define INJ_MAX_FLAGS 0x01FF

struct INJECTIONDATAA
{
	DWORD			LastErrorCode;
	const char		szDllPath[MAX_PATH * 2];
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
};

struct INJECTIONDATAW
{
	DWORD			LastErrorCode;
	const wchar_t	szDllPath[MAX_PATH * 2];
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
};

DWORD __stdcall InjectA(INJECTIONDATAA * pData);
DWORD __stdcall InjectW(INJECTIONDATAW * pData);

#ifdef _WIN64
DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, DWORD & LastError, HINSTANCE & hOut);
#endif

#define INJ_ERR_SUCCESS					0x00000000
#define INJ_ERR_INVALID_PROC_HANDLE		0x00000001	//win32 error set
#define INJ_ERR_FILE_DOESNT_EXIST		0x00000002	//win32 error set
#define INJ_ERR_OUT_OF_MEMORY			0x00000003	//win32 error set
#define INJ_ERR_IMAGE_CANT_RELOC		0x00000004
#define INJ_ERR_LDRLOADDLL_MISSING		0x00000005	//win32 error set
#define INJ_ERR_REMOTEFUNC_MISSING		0x00000006	//win32 error set
#define INJ_ERR_CANT_FIND_MOD_PEB		0x00000007
#define INJ_ERR_WPM_FAIL				0x00000008	//win32 error set
#define INJ_ERR_CANT_ACCESS_PEB			0x00000009	//win32 error set
#define INJ_ERR_CANT_ACCESS_PEB_LDR		0x0000000A	//win32 error set
#define INJ_ERR_VPE_FAIL				0x0000000B	//win32 error set
#define INJ_ERR_CANT_ALLOC_MEM			0x0000000C	//win32 error set
#define	INJ_ERR_RPM_FAIL				0x0000000D	//win32 error set
#define INJ_ERR_INVALID_PID				0x0000000E
#define INJ_ERR_INVALID_FILEPATH		0x0000000F
#define INJ_ERR_CANT_OPEN_PROCESS		0x00000010	//win32 error set
#define INJ_ERR_PLATFORM_MISMATCH		0x00000011
#define INJ_ERR_NO_HANDLES				0x00000012
#define INJ_ERR_CANT_OPEN_OWNER_PROC	0x00000013	//win32 error set
#define INJ_ERR_HIJACK_INJ_FAILED		0x00000014
#define INJ_ERR_HIJACK_CANT_ALLOC		0x00000015	//win32 error set
#define INJ_ERR_HIJACK_CANT_WPM			0x00000016	//win32 error set
#define INJ_ERR_HIJACK_RCE_FAIL			0x00000017
#define INJ_ERR_HIJACK_INJECTW_MISSING	0x00000018
#define INJ_ERR_HIJACK_NO_NATIVE_HANDLE	0x00000019



#define RELOC_FLAG86(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
	#define RELOC_FLAG RELOC_FLAG64
#else
	#define RELOC_FLAG RELOC_FLAG86
#endif

#define ALIGN_UP(X, A) (X + (A - 1)) & (~(A - 1))
#define ALIGN_IMAGE_BASE_X64(Base) ALIGN_UP(Base, 0x10)
#define ALIGN_IMAGE_BASE_X86(Base) ALIGN_UP(Base, 0x08)
#ifdef _WIN64 
#define ALIGN_IMAGE_BASE(Base) ALIGN_IMAGE_BASE_X64(Base)
#else
#define ALIGN_IMAGE_BASE(Base) ALIGN_IMAGE_BASE_X86(Base)
#endif

#define MAXPATH_IN_TCHAR	MAX_PATH
#define MAXPATH_IN_BYTE_A	MAX_PATH * sizeof(char)
#define MAXPATH_IN_BYTE_W	MAX_PATH * sizeof(wchar_t)
#define MAXPATH_IN_BYTE		MAX_PATH * sizeof(TCHAR)

using f_LoadLibraryExW		= decltype(LoadLibraryExW);
using f_LoadLibraryA		= decltype(LoadLibraryA);
using f_GetProcAddress		= UINT_PTR	(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT		= BOOL		(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);
using f_VirtualAlloc		= decltype(VirtualAlloc);
using f_VirtualFree			= decltype(VirtualFree);

struct LOAD_LIBRARY_DATA
{	
	HINSTANCE			hRet;
	f_LoadLibraryExW *	pLoadLibraryExW;
	wchar_t				szDll[MAXPATH_IN_TCHAR];
};

struct LDR_LOAD_DLL_DATA
{
	HANDLE			hRet;
	f_LdrLoadDll	pLdrLoadDll;
	NTSTATUS		ntRet;
	UNICODE_STRING	pModuleFileName;
	BYTE			Data[MAXPATH_IN_BYTE_W];
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

#ifdef _WIN64

struct LOAD_LIBRARY_DATA_WOW64
{	
	DWORD	hRet;
	DWORD	pLoadLibraryExW;
	wchar_t	szDll[MAXPATH_IN_TCHAR];
};

struct LDR_LOAD_DLL_DATA_WOW64
{
	DWORD				hRet;
	DWORD				pLdrLoadDll;
	NTSTATUS			ntRet;
	UNICODE_STRING32	pModuleFileName;
	BYTE				Data[MAXPATH_IN_BYTE_W];
};

struct MANUAL_MAPPING_DATA_WOW64
{
	DWORD hRet;
	DWORD pLoadLibraryA;
	DWORD pGetProcAddress;
	DWORD pVirtualAlloc;
	DWORD pVirtualFree;
	DWORD pModuleBase;
	DWORD Flags;
};

#endif