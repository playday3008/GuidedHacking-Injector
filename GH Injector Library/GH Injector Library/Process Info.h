#pragma once

#include "Tools.h"

class ProcessInfo
{
	SYSTEM_PROCESS_INFORMATION	* m_pCurrentProcess;
	SYSTEM_PROCESS_INFORMATION	* m_pFirstProcess;
	SYSTEM_THREAD_INFORMATION	* m_pCurrentThread;

	ULONG m_BufferSize;

	HANDLE m_hCurrentProcess;

	f_NtQueryInformationProcess m_pNtQueryInformationProcess;
	f_NtQuerySystemInformation	m_pNtQuerySystemInformation;

public:

	ProcessInfo();
	~ProcessInfo();

	bool SetProcess(HANDLE hProc);
	bool SetThread(DWORD TID);
	bool NextThread();

	bool RefreshInformation();

	PEB * GetPEB();
	DWORD GetPID();

	bool IsNative();

	void * GetEntrypoint();

	DWORD GetTID();
	bool GetThreadState(THREAD_STATE & state, KWAIT_REASON & reason);
	bool GetThreadStartAddress(void * & start_address);

	const SYSTEM_PROCESS_INFORMATION	* GetProcessInfo();
	const SYSTEM_THREAD_INFORMATION		* GetThreadInfo();
};