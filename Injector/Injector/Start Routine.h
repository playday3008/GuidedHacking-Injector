#pragma once

#include "Tools.h"
#include "Process Info.h"
#include "Import Handler.h"
#include <vector>

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
};

DWORD StartRoutine(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool HideFromDebugger, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);

#define SR_ERR_SUCCESS				0x00000000
#define SR_ERR_INVALID_PROC_HANDLE	0x10000001	//win32 error set
#define SR_ERR_NTCTE_MISSING		0x10000002	//win32 error set
#define SR_ERR_NTCTE_FAIL			0x10000003	//win32 (ntstatus) error set
#define SR_ERR_CANT_QUERY_INFO		0x10000004
#define SR_ERR_NO_RUNNING_THREADS	0x10000005
#define SR_ERR_CANT_OPEN_THREAD		0x10000006	//win32 error set
#define SR_ERR_SUSPEND_FAIL			0x10000007	//win32 error set
#define SR_ERR_GET_CONTEXT_FAIL		0x10000008	//win32 error set
#define SR_ERR_VAE_FAIL				0x10000009	//win32 error set
#define SR_ERR_WPM_FAIL				0x1000000A	//win32 error set
#define SR_ERR_SET_CONTEXT_FAIL		0x1000000B	//win32 error set
#define SR_ERR_RESUME_FAIL			0x1000000C	//win32 error set
#define SR_ERR_NO_APC_QUEUED		0x1000000D
#define SR_ERR_ENUM_WND_FAIL		0x1000000F	//win32 error set
#define SR_ERR_NO_WINDOWS			0x10000010
#define SR_ERR_RPM_FAIL				0x10000011	//win32 error set
#define SR_ERR_TIMEOUT				0x10000012