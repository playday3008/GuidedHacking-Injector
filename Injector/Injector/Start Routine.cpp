#include "Start Routine.h"

DWORD SR_NtCreateThreadEx	(HANDLE hTargetProc, void * pRoutine, void * pArg, bool HideFromDebugger, DWORD & LastWin32Error, HINSTANCE & hOut);
DWORD SR_HijackThread		(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);
DWORD SR_SetWindowsHookEx	(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);
DWORD SR_QueueUserAPC		(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);

DWORD StartRoutine(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool HideFromDebugger, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	DWORD dwFlags = 0;
	if (!GetHandleInformation(hTargetProc, &dwFlags))
		return SR_ERR_INVALID_PROC_HANDLE;

	DWORD Ret = 0;
	
	switch (Method)
	{
		case LM_NtCreateThreadEx:
			Ret = SR_NtCreateThreadEx(hTargetProc, pRoutine, pArg, HideFromDebugger, LastWin32Error, hOut);
			break;

		case LM_HijackThread:
			Ret = SR_HijackThread(hTargetProc, pRoutine, pArg, CC, LastWin32Error, hOut);
			break;

		case LM_SetWindowsHookEx:
			Ret = SR_SetWindowsHookEx(hTargetProc, pRoutine, pArg, CC, LastWin32Error, hOut);
			break;

		case LM_QueueUserAPC:
			Ret = SR_QueueUserAPC(hTargetProc, pRoutine, pArg, CC, LastWin32Error, hOut);
			break;
	}
	
	return Ret;
}

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, void * pRoutine, void * pArg, bool HideFromDebugger, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	auto _NtCTE = ReCa<f_NtCreateThreadEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
	if (!_NtCTE)
	{
		LastWin32Error = GetLastError();
		return SR_ERR_NTCTE_MISSING;
	}

	HANDLE hThread = nullptr;
	NTSTATUS ntRet = _NtCTE(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRoutine, pArg, ((HideFromDebugger == true) ? THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER : NULL), 0, 0, 0, nullptr);

	if (!hThread || NT_FAIL(ntRet))
	{
		LastWin32Error = static_cast<DWORD>(ntRet);
		return SR_ERR_NTCTE_FAIL;
	}

	DWORD dwExitCode = STILL_ACTIVE;
	while (dwExitCode == STILL_ACTIVE && GetExitCodeThread(hThread, &dwExitCode))
		Sleep(10);
	
	CloseHandle(hThread);

	ReadProcessMemory(hTargetProc, pArg, &hOut, sizeof(hOut), nullptr);

	return SR_ERR_SUCCESS;
}

DWORD SR_HijackThread(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	ProcessInfo pi;
	if (!pi.SetProcess(hTargetProc))
	{
		return SR_ERR_CANT_QUERY_INFO;
	}

	DWORD ThreadID = 0;
	DWORD currentThreadID = GetCurrentThreadId();
	do
	{
		KWAIT_REASON reason;
		THREAD_STATE state;
		if (!pi.GetThreadState(state, reason))
			continue;

		if (state == Running || reason != WrQueue)
		{
			ThreadID = pi.GetTID();
			if(ThreadID != currentThreadID)
				break;
		}

	} while (pi.NextThread());

	if (!ThreadID)
	{
		return SR_ERR_NO_RUNNING_THREADS;
	}
	
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);
	if (!hThread)
	{
		LastWin32Error = GetLastError();
		return SR_ERR_CANT_OPEN_THREAD;
	}

	if (SuspendThread(hThread) == (DWORD)-1)
	{
		LastWin32Error = GetLastError();

		CloseHandle(hThread);

		return SR_ERR_SUSPEND_FAIL;
	}

	CONTEXT OldContext;
	OldContext.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(hThread, &OldContext))
	{
		LastWin32Error = GetLastError();

		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_ERR_GET_CONTEXT_FAIL;
	}

	void * pCodecave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pCodecave)
	{
		LastWin32Error = GetLastError();

		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_ERR_VAE_FAIL;
	}

	ULONG CheckByteOffset = 0;

#ifdef _WIN64

	UNREFERENCED_PARAMETER(CC); //__fastcall assumed as it is the default and basically only calling convention on x64 (besides __vectorcall)
	CheckByteOffset = 3 + 8;

	BYTE Shellcode[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// - 0x08			-> returned value				;buffer to store returned value (rax)	
		
		0x48, 0x83, 0xEC, 0x08,												// + 0x00			-> sub rsp, 0x08				;prepare stack for ret

		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,							// + 0x04 (+ 0x07)	-> mov [rsp], RipLowPart		;store old rip as return address
		0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,						// + 0x0B (+ 0x0F)	-> mov [rsp + 04], RipHighPart		

		0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,	// + 0x13			-> push r(acd)x / r(8-11)		;save registers
		0x9C,																// + 0x1E			-> pushfq

		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// + 0x1F (+ 0x21)	-> mov rax, pFunc
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// + 0x29 (+ 0x2B)	-> mov rcx, pArg				;load pArg into rcx (__fastcall)

		0x48, 0x83, 0xEC, 0x20,												// + 0x33			-> sub rsp, 0x20
		0xFF, 0xD0,															// + 0x37			-> call rax						;call pFunc
		0x48, 0x83, 0xC4, 0x20,												// + 0x39			-> add rsp, 0x20

		0x48, 0x8D, 0x0D, 0xB4, 0xFF, 0xFF, 0xFF,							// + 0x3D			-> lea rcx, [pCodecave - 0x08]	;load address of retval buffer into rcx
		0x48, 0x89, 0x01,													// + 0x44			-> mov [rcx], rax				;store returned value

		0x9D,																// + 0x47			-> popfq						;restore registers
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,	// + 0x48			-> pop r(11-8) / r(dca)x

		0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00,							// + 0x53			-> mov byte ptr[$ - 0x57], 0	;set checkbyte to 0

		0xC3																// + 0x5A			-> ret							;return
	}; // SIZE = 0x5B

	DWORD dwLoRIP = (DWORD)(OldContext.Rip & 0xFFFFFFFF);
	DWORD dwHiRIP = (DWORD)((OldContext.Rip >> 0x20) & 0xFFFFFFFF);

	*ReCa<DWORD*>(Shellcode + 0x07 + 0x08) = dwLoRIP;
	*ReCa<DWORD*>(Shellcode + 0x0F + 0x08) = dwHiRIP;
	*ReCa<void**>(Shellcode + 0x21 + 0x08) = pRoutine;
	*ReCa<void**>(Shellcode + 0x2B + 0x08) = pArg;

	OldContext.Rip = ReCa<DWORD64>(pCodecave) + 0x08;

#else

	CheckByteOffset = 0x02 + 0x04;

	BYTE Shellcode[] =
	{
		0x00, 0x00, 0x00, 0x00,						// - 0x04				-> returned value						;buffer to store returned value (eax)

		0x83, 0xEC, 0x04,							// + 0x00				-> sub esp, 0x04						;prepare stack for ret
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov [esp], OldEip					;store old eip as return address

		0x9C,										// + 0x0A				-> pushad								;save registers
		0x60,										// + 0x0B				-> pushfd

		0xB9, 0x00, 0x00, 0x00, 0x00,				// + 0x0C (+ 0x0D)		-> mov ecx, pArg						;load pArg into ecx
		0xB8, 0x00, 0x00, 0x00, 0x00,				// + 0x11 (+ 0x12)		-> mov eax, pFunc

		0x51,										// + 0x16 (__stdcall)	-> push ecx	(default)					;push pArg (__cdecl/__stdcall)
													// + 0x16 (__cdecl)		-> push ecx (default)
		//0x90,										// + 0x16 (__fastcall)	-> nop									;pArg is already stored in ecx (__fastcall)
		0xFF, 0xD0,									// + 0x17				-> call eax								;call target function
		0x90, 0x90, 0x90,							// + 0x19 (__stdcall)	-> nop (default)						;no need for stack cleanup (__stdcall/__fastcall)
													// + 0x19 (__fastcall)	-> nop (default)
		//0x83, 0xC4, 0x04,							// + 0x19 (__cdecl)		-> add esp, 0x04						;fix stack (__cdecl)

		0xA3, 0x00, 0x00, 0x00, 0x00,				// + 0x1C (+ 0x1D)		-> mov dword ptr[pCodecave - 0x04], eax	;store returned value

		0x61,										// + 0x21				-> popad								;restore registers
		0x9D,										// + 0x22				-> popfd
		
		0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x23 (+ 0x25)		-> mov byte ptr[pCodecave + 0x02], 0x00	;set checkbyte to 0

		0xC3										// + 0x2A				-> ret									;return
	}; // SIZE = 0x2B

	if (CC == CALLCONV::CC_CDECL)
	{
		*(Shellcode + 0x16) = 0x83;
		*(Shellcode + 0x17) = 0xC4;
		*(Shellcode + 0x18) = 0x04;
	}
	else if (CC == CALLCONV::CC_FASTCALL)
	{
		*(Shellcode + 0x16) = 0x90;
	}

	*ReCa<DWORD*>(Shellcode + 0x06 + 0x04) = OldContext.Eip;
	*ReCa<void**>(Shellcode + 0x0D + 0x04) = pArg;
	*ReCa<void**>(Shellcode + 0x12 + 0x04) = pRoutine;
	*ReCa<BYTE**>(Shellcode + 0x1D + 0x04) = reinterpret_cast<BYTE*>(pCodecave);
	*ReCa<BYTE**>(Shellcode + 0x25 + 0x04) = reinterpret_cast<BYTE*>(pCodecave) + 0x02 + 0x04;

	OldContext.Eip = ReCa<DWORD>(pCodecave) + 0x04;

#endif

	if (!WriteProcessMemory(hTargetProc, pCodecave, Shellcode, sizeof(Shellcode), nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_ERR_WPM_FAIL;
	}

	if (!SetThreadContext(hThread, &OldContext))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_ERR_SET_CONTEXT_FAIL;
	}

	if (ResumeThread(hThread) == (DWORD)-1)
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
		CloseHandle(hThread);
		
		return SR_ERR_RESUME_FAIL;
	}

	CloseHandle(hThread);
	
	DWORD TimeOut = GetTickCount();
	BYTE CheckByte = 1;
	while (CheckByte)
	{
		ReadProcessMemory(hTargetProc, reinterpret_cast<BYTE*>(pCodecave) + CheckByteOffset, &CheckByte, 1, nullptr);
		Sleep(10);
		if (GetTickCount() - TimeOut > 5000)
			return SR_ERR_TIMEOUT;
	}

	ReadProcessMemory(hTargetProc, pCodecave, &hOut, sizeof(hOut), nullptr);

	VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

	return SR_ERR_SUCCESS;
}

DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	void * pCodecave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pCodecave)
	{
		LastWin32Error = GetLastError();
		return SR_ERR_VAE_FAIL;
	}

	ULONG CheckByteOffset	= 0;
	ULONG CodeOffset		= 0;
	
	void * pCallNextHookEx = nullptr;
	GetImportA(hTargetProc, "user32.dll", "CallNextHookEx", pCallNextHookEx);

#ifdef _WIN64

	UNREFERENCED_PARAMETER(CC);
	CheckByteOffset = 0x19 + 0x18;
	CodeOffset		= (ULONG)(sizeof(void*) * 3);

	BYTE Shellcode[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// - 0x18	-> pArg / returned value / rax	;buffer
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// - 0x10	-> pFunc						;pointer to target function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// - 0x08	-> CallNextHookEx				;pointer to CallNextHookEx

		0x55,											// + 0x00	-> push rbp						;save important registers
		0x54,											// + 0x01	-> push rsp
		0x53,											// + 0x02	-> push rbx

		0x48, 0x8D, 0x1D, 0xDE, 0xFF, 0xFF, 0xFF,		// + 0x03	-> lea rbx, [pArg]				;load pointer into rbx
		
		0x48, 0x83, 0xEC, 0x20,							// + 0x0A	-> sub rsp, 0x20
		0xFF, 0x53, 0x10,								// + 0x0E	-> call [rbx + 0x10]			;call CallNextHookEx
		0x48, 0x83, 0xC4, 0x20,							// + 0x11	-> add rsp, 0x20

		0x48, 0x8B, 0xC8,								// + 0x15	-> mov rcx, rax					;copy retval into rcx

		0xEB, 0x00,										// + 0x18	-> jmp $ + 0x02					;jmp to next instruction
		0xC6, 0x05, 0xF8, 0xFF, 0xFF, 0xFF, 0x18,		// + 0x1A	-> mov byte ptr[$ - 0x01], 0x1A	;hotpatch jmp above to skip shellcode

		0x48, 0x87, 0x0B,								// + 0x21	-> xchg [rbx], rcx				;store CallNextHookEx retval, load pArg
		0x48, 0x83, 0xEC, 0x20,							// + 0x24	-> sub rsp, 0x20
		0xFF, 0x53, 0x08,								// + 0x28	-> call [rbx + 0x08]			;call pFunc
		0x48, 0x83, 0xC4, 0x20,							// + 0x2B	-> add rsp, 0x20

		0x48, 0x87, 0x03,								// + 0x2F	-> xchg [rbx], rax				;store pFunc retval, restore CallNextHookEx retval

		0x5B,											// + 0x32	-> pop rbx						;restore important registers
		0x5C,											// + 0x33	-> pop rsp
		0x5D,											// + 0x34	-> pop rbp

		0xC3											// + 0x36	-> ret							;return
	}; // SIZE = 0x37 (+ 0x18)

	*ReCa<void**>(Shellcode + 0x00) = pArg;
	*ReCa<void**>(Shellcode + 0x08) = pRoutine;
	*ReCa<void**>(Shellcode + 0x10) = pCallNextHookEx;

#else

	CheckByteOffset = 0x14 + 0x08;
	CodeOffset		= (ULONG)(sizeof(void*) * 2);
	
	BYTE Shellcode[] =
	{
		0x00, 0x00, 0x00, 0x00,			// - 0x08				-> pArg						;pointer to argument
		0x00, 0x00, 0x00, 0x00,			// - 0x04				-> pFunc					;pointer to target function

		0x55,							// + 0x00				-> push ebp					;x86 stack frame creation
		0x8B, 0xEC,						// + 0x01				-> mov ebp, esp

		0xFF, 0x75, 0x10,				// + 0x03				-> push [ebp + 0x10]		;push CallNextHookEx arguments
		0xFF, 0x75, 0x0C,				// + 0x06				-> push [ebp + 0x0C] 
		0xFF, 0x75, 0x08, 				// + 0x09				-> push [ebp + 0x08]
		0x6A, 0x00,						// + 0x0C				-> push 0x00
		0xE8, 0x00, 0x00, 0x00, 0x00,	// + 0x0E (+ 0x0F)		-> call CallNextHookEx		;call CallNextHookEx

		0xEB, 0x00,						// + 0x13				-> jmp $ + 0x02				;jmp to next instruction

		0x50,							// + 0x15				-> push eax					;save eax (CallNextHookEx retval)
		0x53,							// + 0x16				-> push ebx					;save ebx (non volatile)

		0xBB, 0x00, 0x00, 0x00, 0x00,	// + 0x17 (+ 0x18)		-> mov ebx, pArg			;move pArg (pCodecave) into ebx
		0xC6, 0x43, 0x1C, 0x17,			// + 0x1C				-> mov [ebx + 0x1C], 0x17	;hotpatch jmp above to skip shellcode

		0xFF, 0x33,						// + 0x20 (__stdcall)	-> push [ebx] (default)		;push pArg (__cdecl/__stdcall)
										// + 0x20 (__cdecl)		-> push [ebx] (default)
		//0x8B, 0x0B,					// + 0x20 (__fastcall)	-> mov ecx, [ebx]			;move pArg into ecx (__fastcall)

		0xFF, 0x53, 0x04,				// + 0x22				-> call [ebx + 0x04]		;call target function

		0x90, 0x90, 0x90,				// + 0x25 (__stdcall)	-> nop (default)			;no need for stack cleanup (__stdcall/__fastcall)
										// + 0x25 (__fastcall)	-> nop (default)
		//0x83, 0xC4, 0x04,				// + 0x25 (__cdecl)		-> add esp, 0x04			;fix stack (__cdecl)

		0x89, 0x03,						// + 0x28				-> mov [ebx], eax			;store returned value

		0x5B,							// + 0x2A				-> pop ebx					;restore old ebx
		0x58,							// + 0x2B				-> pop eax					;restore eax (CallNextHookEx retval)

		0x5D,							// + 0x2C				-> pop ebp					;restore ebp
		0xC2, 0x0C, 0x00				// + 0x2D				-> ret 0x0C					;return
	}; // SIZE = 0x30 (+ 0x08)

	if (CC == CALLCONV::CC_CDECL)
	{
		*(Shellcode + 0x25 + 0x08) = 0x83;
		*(Shellcode + 0x26 + 0x08) = 0xC4;
		*(Shellcode + 0x27 + 0x08) = 0x04;
	}
	else if (CC == CALLCONV::CC_FASTCALL)
	{
		*(Shellcode + 0x20 + 0x08) = 0x8B;
		*(Shellcode + 0x21 + 0x08) = 0x0B;
	}

	*ReCa<void**>(Shellcode + 0x00) = pArg;
	*ReCa<void**>(Shellcode + 0x04) = pRoutine;

	*ReCa<void**>(Shellcode + 0x18 + 0x08) = pCodecave;
	*ReCa<DWORD*>(Shellcode + 0x0F + 0x08) = ReCa<DWORD>(pCallNextHookEx) - (ReCa<DWORD>(pCodecave) + 0x0E + 0x08) - 5;

#endif

	if (!WriteProcessMemory(hTargetProc, pCodecave, Shellcode, sizeof(Shellcode), nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

		return SR_ERR_WPM_FAIL;
	}

	EnumWindowsCallback_Data data;
	data.m_pHook = reinterpret_cast<HOOKPROC>(reinterpret_cast<BYTE*>(pCodecave) + CodeOffset);
	data.m_hProc = hTargetProc;

	if (!EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&data)))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

		return SR_ERR_ENUM_WND_FAIL;
	}

	if (data.m_HookData.empty())
	{
		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

		return SR_ERR_NO_WINDOWS;
	}

	for (auto i : data.m_HookData)
	{
		SetForegroundWindow(i.m_hWnd);
		SendMessageA(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(10);
		SendMessageA(i.m_hWnd, WM_KEYUP, VK_SPACE, 0);
		UnhookWindowsHookEx(i.m_hHook);
	}
	
	DWORD TimeOut = GetTickCount();
	BYTE CheckByte = 0;
	while (!CheckByte)
	{
		ReadProcessMemory(hTargetProc, reinterpret_cast<BYTE*>(pCodecave) + CheckByteOffset, &CheckByte, 1, nullptr);
		Sleep(10);
		if (GetTickCount() - TimeOut > 5000)
			return SR_ERR_TIMEOUT;
	}

	ReadProcessMemory(hTargetProc, pCodecave, &hOut, sizeof(hOut), nullptr);
	
	VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
	
	return SR_ERR_SUCCESS;
}

DWORD SR_QueueUserAPC(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	UNREFERENCED_PARAMETER(CC); //QueueUserAPC only supports __stdcall (x86) and __fastcall (x64)

	ProcessInfo pi;
	if (!pi.SetProcess(hTargetProc))
	{
		return SR_ERR_CANT_QUERY_INFO;
	}

	HINSTANCE hOld0 = NULL;
	if (!ReadProcessMemory(hTargetProc, pArg, &hOld0, sizeof(hOld0), nullptr))
	{
		LastWin32Error = GetLastError();
		return SR_ERR_RPM_FAIL;
	}
	
	bool APC_queued = false;
	
	do
	{
		KWAIT_REASON reason;
		THREAD_STATE state;
		if (!pi.GetThreadState(state, reason))
			continue;

		if (state == Running || reason != WrQueue)
		{
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, pi.GetTID());
			if (hThread)
				if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(pRoutine), hThread, reinterpret_cast<ULONG_PTR>(pArg)))
					APC_queued = true;
				
		}

	} while (pi.NextThread());

	if (!APC_queued)
	{
		return SR_ERR_NO_APC_QUEUED;
	}
	
	DWORD TimeOut = GetTickCount();
	HINSTANCE hOld1 = hOld0;
	while (hOld0 == hOld1)
	{
		ReadProcessMemory(hTargetProc, pArg, &hOld1, sizeof(hOld1), nullptr);
		Sleep(10);
		if (GetTickCount() - TimeOut > 5000)
			return SR_ERR_TIMEOUT;
	}

	hOut = hOld1;

	return SR_ERR_SUCCESS;
}

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	auto * pData = reinterpret_cast<EnumWindowsCallback_Data*>(lParam);
	DWORD PID = GetProcessId(pData->m_hProc);
	
	DWORD winPID = 0;
	DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);
	if (winPID == PID)
	{
		char szWindow[MAX_PATH]{ 0 };
		if (IsWindowVisible(hWnd) && GetWindowTextA(hWnd, szWindow, MAX_PATH))
		{
			if (GetClassNameA(hWnd, szWindow, MAX_PATH) && strcmp(szWindow, "ConsoleWindowClass"))
			{
				HHOOK hHook = SetWindowsHookExA(WH_CALLWNDPROC, pData->m_pHook, GetModuleHandleA("kernel32.dll"), winTID);
				if (hHook)
				{
					pData->m_HookData.push_back({ hHook, hWnd });
				}
			}
		}
	}

	return TRUE;
}