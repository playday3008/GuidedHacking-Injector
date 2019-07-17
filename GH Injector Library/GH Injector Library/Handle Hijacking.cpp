#include "Handle Hijacking.h"

NTSTATUS EnumHandles(char * pBuffer, ULONG Size, ULONG * SizeOut, UINT & Count);
std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> EnumProcessHandles();

NTSTATUS EnumHandles(char * pBuffer, ULONG Size, ULONG * SizeOut, UINT & Count)
{
	auto p_NtQuerySystemInformation = reinterpret_cast<f_NtQuerySystemInformation>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
	if (!p_NtQuerySystemInformation)
		return -1;

	NTSTATUS ntRet = p_NtQuerySystemInformation(SystemHandleInformation, pBuffer, Size, SizeOut);

	if (NT_FAIL(ntRet))
		return ntRet;

	auto * pHandleInfo	= reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(pBuffer);
	Count = pHandleInfo->NumberOfHandles;
	
	return ntRet;
}

std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> EnumProcessHandles()
{
	UINT Count		= 0;
	ULONG Size		= 0x10000;
	char * pBuffer	= new char[Size];
	NTSTATUS ntRet	= EnumHandles(pBuffer, Size, &Size, Count);

	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> Ret;

	if (NT_FAIL(ntRet))
	{
		while (ntRet == 0xC0000004) //STATUS_INFO_LENGTH_MISMATCH
		{
			delete[] pBuffer;
			pBuffer = new char[Size];
			ntRet = EnumHandles(pBuffer, Size, &Size, Count);
		}

		if (NT_FAIL(ntRet))
		{
			delete[] pBuffer;
			return Ret;
		}
	}

	auto * pEntry = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(pBuffer)->Handles;
	for (UINT i = 0; i != Count; ++i)
		if (pEntry[i].ObjectTypeIndex == OTI_Process)
			Ret.push_back(pEntry[i]);
		
	delete[] pBuffer;

	return Ret;
}

std::vector <handle_data> FindProcessHandles(DWORD TargetPID, DWORD WantedHandleAccess)
{
	std::vector <handle_data> Ret;
	DWORD OwnerPID		= 0;
	HANDLE hOwnerProc	= nullptr;

	for (auto i : EnumProcessHandles())
	{
		if (OwnerPID != i.UniqueProcessId)
		{
			if (hOwnerProc)
				CloseHandle(hOwnerProc);

			OwnerPID = i.UniqueProcessId;
			hOwnerProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, OwnerPID);

			if (!hOwnerProc)
				continue;
		}
		else if (!hOwnerProc)
			continue;
		
		HANDLE hDup		= nullptr;
		HANDLE hOrig	= reinterpret_cast<HANDLE>(i.HandleValue);
		NTSTATUS ntRet	= DuplicateHandle(hOwnerProc, hOrig, GetCurrentProcess(), &hDup, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0);
		if (NT_FAIL(ntRet))
			continue;
		
		if (GetProcessId(hDup) == TargetPID && (i.GrantedAccess - (i.GrantedAccess ^ WantedHandleAccess) == WantedHandleAccess))
		{
			Ret.push_back(handle_data{ OwnerPID, i.HandleValue, i.GrantedAccess });
		}
			
		CloseHandle(hDup);
	}

	if (hOwnerProc)
		CloseHandle(hOwnerProc);

	return Ret;
}