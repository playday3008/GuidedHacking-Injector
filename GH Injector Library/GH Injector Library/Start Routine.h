#pragma once

#include "Process Info.h"
#include "Import Handler.h"

#ifdef ReCa
#undef ReCa
#endif
#define ReCa reinterpret_cast

enum LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC
};

struct HookData
{
	HHOOK	m_hHook;
	HWND	m_hWnd;
};

struct EnumWindowsCallback_Data
{
	std::vector<HookData>	m_HookData;
	HANDLE					m_hProc;
	HOOKPROC				m_pHook;
	HINSTANCE				m_hModule;
};

#define SWHEX_EXE_FILENAME64 L"GH Injector SWHEX - x64.exe"
#define SWHEX_EXE_FILENAME86 L"GH Injector SWHEX - x86.exe"

#define SWHEX_INFO_FILENAME64 L"SWHEX64.txt"
#define SWHEX_INFO_FILENAME86 L"SWHEX86.txt"

#ifdef _WIN64
#define SWHEX_INFO_FILENAME SWHEX_INFO_FILENAME64
#define SWHEX_EXE_FILENAME SWHEX_EXE_FILENAME64
#else
#define SWHEX_INFO_FILENAME SWHEX_INFO_FILENAME86
#define SWHEX_EXE_FILENAME SWHEX_EXE_FILENAME86
#endif

DWORD StartRoutine(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool CloakThread, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);

#ifdef _WIN64
DWORD StartRoutine_WOW64(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool CloakThread, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);
#endif

#define SR_ERR_SUCCESS					0x00000000
#define SR_ERR_INVALID_PROC_HANDLE		0x10000001	//win32 error set
#define SR_ERR_NTCTE_MISSING			0x10000002	//win32 error set
#define SR_ERR_NTCTE_FAIL				0x10000003	//win32 (ntstatus) error set
#define SR_ERR_CANT_QUERY_INFO			0x10000004
#define SR_ERR_NO_RUNNING_THREADS		0x10000005
#define SR_ERR_CANT_OPEN_THREAD			0x10000006	//win32 error set
#define SR_ERR_SUSPEND_FAIL				0x10000007	//win32 error set
#define SR_ERR_GET_CONTEXT_FAIL			0x10000008	//win32 error set
#define SR_ERR_VAE_FAIL					0x10000009	//win32 error set
#define SR_ERR_WPM_FAIL					0x1000000A	//win32 error set
#define SR_ERR_SET_CONTEXT_FAIL			0x1000000B	//win32 error set
#define SR_ERR_RESUME_FAIL				0x1000000C	//win32 error set
#define SR_ERR_NO_APC_QUEUED			0x1000000D
#define SR_ERR_ENUM_WND_FAIL			0x1000000F	//win32 error set
#define SR_ERR_NO_WINDOWS				0x10000010
#define SR_ERR_RPM_FAIL					0x10000011	//win32 error set
#define SR_ERR_TIMEOUT					0x10000012
#define SR_ERR_REMOTEFUNC_MISSING		0x10000013	//win32 error set
#define SR_ERR_RTLQAW64_MISSING			0x10000014	//win32 error set
#define SR_ERR_CANT_QUERY_SESSION_ID	0x10000015	//win32 (ntstatus) error set
#define SR_ERR_CANT_QUERY_INFO_PATH		0x10000016
#define SR_ERR_CANT_OPEN_INFO_TXT		0x10000017
#define SR_ERR_WTSQUERY_FAIL			0x10000018	//win32 error set
#define SR_ERR_DUP_TOKEN_FAIL			0x10000019	//win32 error set
#define SR_ERR_GET_ADMIN_TOKEN_FAIL		0x1000001A	//win32 error set
#define SR_ERR_CANT_CREATE_PROCESS		0x1000001B	//win32 error set