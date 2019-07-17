#include "Process Info.h"

#pragma comment(lib, "Psapi.lib")

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define NEXT_SYSTEM_PROCESS_ENTRY(pCurrent) reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<BYTE*>(pCurrent) + pCurrent->NextEntryOffset)

ProcessInfo::ProcessInfo()
{
	m_BufferSize	= 0x10000;
	m_pFirstProcess = nullptr;

	HINSTANCE hNTDLL = GetModuleHandleA("ntdll.dll");
	m_pNtQueryInformationProcess	= reinterpret_cast<f_NtQueryInformationProcess>	(GetProcAddress(hNTDLL, "NtQueryInformationProcess"));
	m_pNtQuerySystemInformation		= reinterpret_cast<f_NtQuerySystemInformation>	(GetProcAddress(hNTDLL, "NtQuerySystemInformation"));

	RefreshInformation();
}

ProcessInfo::~ProcessInfo()
{
	if (m_pFirstProcess)
		delete[] m_pFirstProcess;
}

bool ProcessInfo::SetProcess(HANDLE hProc)
{
	if (!hProc)
		return false;

	if (!m_pFirstProcess)
		if (!RefreshInformation())
			return false;

	m_hCurrentProcess = hProc;

	UINT_PTR PID = GetProcessId(m_hCurrentProcess);

	while (NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess) != m_pCurrentProcess)
	{
		if (m_pCurrentProcess->UniqueProcessId == reinterpret_cast<void*>(PID))
			break;

		m_pCurrentProcess = NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess);
	}

	if (m_pCurrentProcess->UniqueProcessId != reinterpret_cast<void*>(PID))
	{
		m_pCurrentProcess = m_pFirstProcess;
		return false;
	}

	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;	
}

bool ProcessInfo::SetThread(DWORD TID)
{
	if (!m_pFirstProcess)
		if (!RefreshInformation())
			return false;

	m_pCurrentThread = nullptr;

	for (UINT i = 0; i != m_pCurrentProcess->NumberOfThreads; ++i)
	{
		if (m_pCurrentProcess->Threads[i].ClientId.UniqueThread == reinterpret_cast<void*>(UINT_PTR(TID)))
		{
			m_pCurrentThread = &m_pCurrentProcess->Threads[i];
			break;
		}
	}
	
	if (m_pCurrentThread == nullptr)
	{
		m_pCurrentThread = &m_pCurrentProcess->Threads[0];
		return false;
	}

	return true;
}

bool ProcessInfo::NextThread()
{
	if (!m_pFirstProcess)
		if (!RefreshInformation())
			return false;

	for (UINT i = 0; i != m_pCurrentProcess->NumberOfThreads; ++i)
	{
		if (m_pCurrentProcess->Threads[i].ClientId.UniqueThread == m_pCurrentThread->ClientId.UniqueThread)
		{
			if (i + 1 != m_pCurrentProcess->NumberOfThreads)
			{
				m_pCurrentThread++;
				return true;
			}
			else
			{
				m_pCurrentThread = &m_pCurrentProcess->Threads[0];
				return false;
			}
		}
	}
		
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return false;
}

bool ProcessInfo::RefreshInformation()
{
	if (!m_pFirstProcess)
	{
		m_pFirstProcess = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(new BYTE[m_BufferSize]);
		if (!m_pFirstProcess)
			return false;
	}
	else
	{
		delete[] m_pFirstProcess;
		m_pFirstProcess = nullptr;

		return RefreshInformation();
	}

	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQuerySystemInformation(SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);

	while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete[] m_pFirstProcess;

		m_BufferSize = size_out + 0x1000;
		m_pFirstProcess = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(new BYTE[m_BufferSize]);
		if (!m_pFirstProcess)
			return false;

		ntRet = m_pNtQuerySystemInformation(SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
	}

	if (NT_FAIL(ntRet))
	{
		delete[] m_pFirstProcess;
		m_pFirstProcess = nullptr;

		return false;
	}

	m_pCurrentProcess = m_pFirstProcess;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

PEB * ProcessInfo::GetPEB()
{
	if (!m_pFirstProcess)
		return false;
	
	PROCESS_BASIC_INFORMATION PBI{ 0 };
	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQueryInformationProcess(m_hCurrentProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &size_out);
	
	if (NT_FAIL(ntRet))
		return nullptr;
	
	return PBI.pPEB;
}

DWORD ProcessInfo::GetPID()
{
	return GetProcessId(m_hCurrentProcess);
}

bool ProcessInfo::IsNative()
{
	BOOL bOut = FALSE;
	IsWow64Process(m_hCurrentProcess, &bOut);
	return (bOut == FALSE);
}

void * ProcessInfo::GetEntrypoint()
{
	if (!m_pFirstProcess)
		return nullptr;

	PEB * ppeb = GetPEB();
	if (!ppeb)
		return nullptr;

	PEB	peb;
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(PEB), nullptr))
		return nullptr;

	PEB_LDR_DATA ldrdata;
	if (!ReadProcessMemory(m_hCurrentProcess, peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA), nullptr))
		return nullptr;

	LIST_ENTRY * pCurrentEntry	= ldrdata.InLoadOrderModuleListHead.Flink;
	LIST_ENTRY * pLastEntry		= ldrdata.InLoadOrderModuleListHead.Blink;
	
	wchar_t NameBuffer[MAX_PATH]{ 0 };
	while (true)
	{
		LDR_DATA_TABLE_ENTRY CurrentEntry;
		if (ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))
		{
			if (ReadProcessMemory(m_hCurrentProcess, CurrentEntry.BaseDllName.szBuffer, NameBuffer, CurrentEntry.BaseDllName.Length, nullptr))
			{
				if (NameBuffer[CurrentEntry.BaseDllName.Length / 2 - 1] == 'e')
				{
					return CurrentEntry.EntryPoint;
				}
			}
		}

		if (pCurrentEntry == pLastEntry)
			break;
		else
			pCurrentEntry = CurrentEntry.InLoadOrder.Flink;
	}

	return nullptr;
}

DWORD ProcessInfo::GetTID()
{
	if (!m_pFirstProcess)
		return 0;

	return DWORD(reinterpret_cast<UINT_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

bool ProcessInfo::GetThreadState(THREAD_STATE & state, KWAIT_REASON & reason)
{
	if (!m_pFirstProcess)
		return false;

	state	= m_pCurrentThread->ThreadState;
	reason	= m_pCurrentThread->WaitReason;

	return true;
}

bool ProcessInfo::GetThreadStartAddress(void *& start_address)
{
	if (!m_pFirstProcess)
		return false;

	start_address = m_pCurrentThread->StartAddress;

	return true;
}

const SYSTEM_PROCESS_INFORMATION * ProcessInfo::GetProcessInfo()
{
	if (m_pFirstProcess)
		return m_pCurrentProcess;

	return nullptr;
}

const SYSTEM_THREAD_INFORMATION * ProcessInfo::GetThreadInfo()
{
	if (m_pFirstProcess)
		return m_pCurrentThread;

	return nullptr;
}