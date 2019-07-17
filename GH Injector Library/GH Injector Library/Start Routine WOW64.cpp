#ifdef _WIN64

#include "Start Routine.h"

DWORD SR_NtCreateThreadEx_WOW64	(HANDLE hTargetProc, void * pRoutine, void * pArg, bool CloakThread, DWORD & LastWin32Error, HINSTANCE & hOut);
DWORD SR_HijackThread_WOW64		(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);
DWORD SR_SetWindowsHookEx_WOW64	(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, ULONG TargetSessionId, HINSTANCE & hOut);
DWORD SR_QueueUserAPC_WOW64		(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut);

DWORD StartRoutine_WOW64(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool CloakThread, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	DWORD Ret = 0;
	
	switch (Method)
	{
		case LM_NtCreateThreadEx:
			Ret = SR_NtCreateThreadEx_WOW64(hTargetProc, pRoutine, pArg, CloakThread, LastWin32Error, hOut);
			break;

		case LM_HijackThread:
			Ret = SR_HijackThread_WOW64(hTargetProc, pRoutine, pArg, CC, LastWin32Error, hOut);
			break;

		case LM_SetWindowsHookEx:
			{
				NTSTATUS ntRet = 0;
				ULONG TargetSession = GetSessionId(hTargetProc, ntRet);
				if (TargetSession == (ULONG)-1)
				{
					LastWin32Error = static_cast<DWORD>(ntRet);
					Ret = SR_ERR_CANT_QUERY_SESSION_ID;
					break;
				}
				else if (TargetSession == GetSessionId(GetCurrentProcess(), ntRet))
				{
					TargetSession = (ULONG)-1;
				}
				Ret = SR_SetWindowsHookEx_WOW64(hTargetProc, pRoutine, pArg, CC, LastWin32Error, TargetSession, hOut);
			}
			break;

		case LM_QueueUserAPC:
			Ret = SR_QueueUserAPC_WOW64(hTargetProc, pRoutine, pArg, CC, LastWin32Error, hOut);
			break;
	}
	
	return Ret;
}

DWORD SR_NtCreateThreadEx_WOW64(HANDLE hTargetProc, void * pRoutine, void * pArg, bool CloakThread, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	auto p_NtCreateThreadEx = ReCa<f_NtCreateThreadEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
	if (!p_NtCreateThreadEx)
	{
		LastWin32Error = GetLastError();
		return SR_ERR_NTCTE_MISSING;
	}

	void * pEntrypoint = pRoutine;
	if (CloakThread)
	{
		ProcessInfo pi;
		pi.SetProcess(hTargetProc);
		pEntrypoint = pi.GetEntrypoint();
	}

	DWORD Flags		= THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	HANDLE hThread	= nullptr;

	NTSTATUS ntRet = p_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pEntrypoint, pArg, ((CloakThread == true) ? Flags : NULL), 0, 0, 0, nullptr);

	if (!hThread || NT_FAIL(ntRet))
	{
		LastWin32Error = static_cast<DWORD>(ntRet);
		return SR_ERR_NTCTE_FAIL;
	}

	if (CloakThread)
	{
		WOW64_CONTEXT ctx;
		ctx.ContextFlags = WOW64_CONTEXT_INTEGER;
		Wow64GetThreadContext(hThread, &ctx);
		ctx.Eax = (DWORD)(UINT_PTR)pRoutine;
		Wow64SetThreadContext(hThread, &ctx);
		ResumeThread(hThread);
	}

	DWORD dwExitCode = STILL_ACTIVE;
	while (dwExitCode == STILL_ACTIVE && GetExitCodeThread(hThread, &dwExitCode))
		Sleep(10);
	
	CloseHandle(hThread);

	DWORD dwOut = 0;
	ReadProcessMemory(hTargetProc, pArg, &dwOut, sizeof(dwOut), nullptr);
	hOut = (HINSTANCE)(UINT_PTR)dwOut;

	LastWin32Error = dwExitCode;

	return SR_ERR_SUCCESS;
}

DWORD SR_HijackThread_WOW64(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
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
	
	if (Wow64SuspendThread(hThread) == (DWORD)-1)
	{
		LastWin32Error = GetLastError();

		CloseHandle(hThread);

		return SR_ERR_SUSPEND_FAIL;
	}

	WOW64_CONTEXT OldContext;
	OldContext.ContextFlags = WOW64_CONTEXT_CONTROL;
	if (!Wow64GetThreadContext(hThread, &OldContext))
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

	ULONG CheckByteOffset = 0x02 + 0x04;

	BYTE Shellcode[] =
	{
		0x00, 0x00, 0x00, 0x00,						// - 0x04				-> returned value						;buffer to store returned value (eax)

		0x83, 0xEC, 0x04,							// + 0x00				-> sub esp, 0x04						;prepare stack for ret
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov [esp], OldEip					;store old eip as return address

		0x9C,										// + 0x0A				-> pushad								;save registers
		0x60,										// + 0x0B				-> pushfd

		0xB9, 0x00, 0x00, 0x00, 0x00,				// + 0x0C (+ 0x0D)		-> mov ecx, pArg						;load pArg into ecx
		0xB8, 0x00, 0x00, 0x00, 0x00,				// + 0x11 (+ 0x12)		-> mov eax, pRoutine

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
	*ReCa<DWORD*>(Shellcode + 0x0D + 0x04) = (DWORD)(UINT_PTR)pArg;
	*ReCa<DWORD*>(Shellcode + 0x12 + 0x04) = (DWORD)(UINT_PTR)pRoutine;
	*ReCa<DWORD*>(Shellcode + 0x1D + 0x04) = (DWORD)(UINT_PTR)pCodecave;
	*ReCa<DWORD*>(Shellcode + 0x25 + 0x04) = (DWORD)(UINT_PTR)pCodecave + 0x02 + 0x04;

	OldContext.Eip = (DWORD)(UINT_PTR)pCodecave + 0x04;

	if (!WriteProcessMemory(hTargetProc, pCodecave, Shellcode, sizeof(Shellcode), nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_ERR_WPM_FAIL;
	}

	if (!Wow64SetThreadContext(hThread, &OldContext))
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

	DWORD dwOut = 0;
	ReadProcessMemory(hTargetProc, pCodecave, &dwOut, sizeof(dwOut), nullptr);
	hOut = (HINSTANCE)(UINT_PTR)dwOut;

	VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

	return SR_ERR_SUCCESS;
}

DWORD SR_SetWindowsHookEx_WOW64(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, ULONG TargetSessionId, HINSTANCE & hOut)
{
	wchar_t RootPath[MAX_PATH * 2]{ 0 };
	if (!GetOwnModulePath(RootPath, sizeof(RootPath) / sizeof(RootPath[0])))
	{
		return SR_ERR_CANT_QUERY_INFO_PATH;
	}

	wchar_t InfoPath[sizeof(RootPath) / sizeof(RootPath[0])]{ 0 };
	memcpy(InfoPath, RootPath, sizeof(RootPath));
	StringCbCatW(InfoPath, sizeof(InfoPath), SWHEX_INFO_FILENAME86);

	if (FileExists(InfoPath))
		DeleteFileW(InfoPath);

	std::wofstream swhex_info(InfoPath, std::ios_base::out | std::ios_base::app);
	if (swhex_info.rdstate() & std::ofstream::failbit)
	{
		swhex_info.close();
		return SR_ERR_CANT_OPEN_INFO_TXT;
	}

	void * pCodecave = VirtualAllocEx(hTargetProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pCodecave)
	{
		LastWin32Error = GetLastError();

		swhex_info.close();

		return SR_ERR_VAE_FAIL;
	}

	void * pCallNextHookEx = nullptr;
	GetProcAddressA_WOW64(hTargetProc, GetModuleHandleExA_WOW64(hTargetProc, "user32.dll"), "CallNextHookEx", pCallNextHookEx);

	ULONG CheckByteOffset	= 0x14 + 0x08;
	ULONG CodeOffset		= (ULONG)(sizeof(DWORD) * 2);
	
	BYTE Shellcode[] =
	{
		0x00, 0x00, 0x00, 0x00,			// - 0x08				-> pArg						;pointer to argument
		0x00, 0x00, 0x00, 0x00,			// - 0x04				-> pRoutine					;pointer to target function

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

	*ReCa<DWORD*>(Shellcode + 0x00) = (DWORD)(UINT_PTR)pArg;
	*ReCa<DWORD*>(Shellcode + 0x04) = (DWORD)(UINT_PTR)pRoutine;

	*ReCa<DWORD*>(Shellcode + 0x18 + 0x08) = (DWORD)(UINT_PTR)pCodecave;
	*ReCa<DWORD*>(Shellcode + 0x0F + 0x08) = (DWORD)(UINT_PTR)(pCallNextHookEx) - ((DWORD)(UINT_PTR)(pCodecave) + 0x0E + 0x08) - 5;

	if (!WriteProcessMemory(hTargetProc, pCodecave, Shellcode, sizeof(Shellcode), nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
		swhex_info.close();

		return SR_ERR_WPM_FAIL;
	}

	swhex_info << std::dec << GetProcessId(hTargetProc) << '!' << std::hex << (DWORD)(UINT_PTR)(pCodecave) + CodeOffset << std::endl;
	swhex_info.close();

	StringCbCatW(RootPath, sizeof(RootPath), SWHEX_EXE_FILENAME86);
	
	PROCESS_INFORMATION pi{ 0 };
	STARTUPINFOW si{ 0 };
	si.cb			= sizeof(si);
	si.dwFlags		= STARTF_USESHOWWINDOW;
	si.wShowWindow	= SW_HIDE;

	if (TargetSessionId != -1) 
	{
		HANDLE hUserToken = nullptr;
		if (!WTSQueryUserToken(TargetSessionId, &hUserToken))
		{
			LastWin32Error = GetLastError();

			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

			return SR_ERR_WTSQUERY_FAIL;
		}

		HANDLE hNewToken = nullptr;
		if (!DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &hNewToken))
		{
			LastWin32Error = GetLastError();

			CloseHandle(hUserToken);
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

			return SR_ERR_DUP_TOKEN_FAIL;
		}

		DWORD SizeOut = 0;
		TOKEN_LINKED_TOKEN admin_token{ 0 };
		if (!GetTokenInformation(hNewToken, TokenLinkedToken, &admin_token, sizeof(admin_token), &SizeOut))
		{
			LastWin32Error = GetLastError();

			CloseHandle(hNewToken);
			CloseHandle(hUserToken);
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

			return SR_ERR_GET_ADMIN_TOKEN_FAIL;
		}
		HANDLE hAdminToken = admin_token.LinkedToken;

		if (!CreateProcessAsUserW(hAdminToken, RootPath, nullptr, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			LastWin32Error = GetLastError();
			
			CloseHandle(hAdminToken);
			CloseHandle(hNewToken);
			CloseHandle(hUserToken);
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

			return SR_ERR_CANT_CREATE_PROCESS;
		}
		
		CloseHandle(hAdminToken);
		CloseHandle(hNewToken);
		CloseHandle(hUserToken);
	}
	else
	{
		if (!CreateProcessW(RootPath, nullptr, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			LastWin32Error = GetLastError();
			
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

			return SR_ERR_CANT_CREATE_PROCESS;
		}
	}
	
	DWORD ExitCode = STILL_ACTIVE;
	while (ExitCode == STILL_ACTIVE && GetExitCodeProcess(pi.hProcess, &ExitCode))
	{
		Sleep(10);
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (ExitCode)
	{
		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
	
		return ExitCode;
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

	hOut = NULL;
	ReadProcessMemory(hTargetProc, pCodecave, &hOut, sizeof(DWORD), nullptr);
	
	VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
	
	return SR_ERR_SUCCESS;
}

DWORD SR_QueueUserAPC_WOW64(HANDLE hTargetProc, void * pRoutine, void * pArg, CALLCONV CC, DWORD & LastWin32Error, HINSTANCE & hOut)
{
	UNREFERENCED_PARAMETER(CC); //QueueUserAPC only supports __stdcall (x86) and __fastcall (x64)

	auto p_RtlQueueApcWow64Thread = reinterpret_cast<f_RtlQueueApcWow64Thread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlQueueApcWow64Thread"));
	if (!p_RtlQueueApcWow64Thread)
	{
		LastWin32Error = GetLastError();
		return SR_ERR_RTLQAW64_MISSING;
	}

	ProcessInfo pi;
	if (!pi.SetProcess(hTargetProc))
	{
		return SR_ERR_CANT_QUERY_INFO;
	}

	DWORD hOld0 = 0;
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
			{
				NTSTATUS ntRet = p_RtlQueueApcWow64Thread(hThread, pRoutine, pArg, nullptr, nullptr);
				CloseHandle(hThread);
				if (NT_SUCCESS(ntRet))
					APC_queued = true;
			}
		}

	} while (pi.NextThread());

	if (!APC_queued)
	{
		return SR_ERR_NO_APC_QUEUED;
	}
	
	DWORD TimeOut = GetTickCount();
	DWORD hOld1 = hOld0;
	while (hOld0 == hOld1)
	{
		ReadProcessMemory(hTargetProc, pArg, &hOld1, sizeof(hOld1), nullptr);
		Sleep(10);
		if (GetTickCount() - TimeOut > 5000)
			return SR_ERR_TIMEOUT;
	}

	hOut = (HINSTANCE)(UINT_PTR)hOld1;

	return SR_ERR_SUCCESS;
}

#endif