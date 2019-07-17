#ifdef _WIN64

#include "Import Handler.h"

#ifdef UNICODE
#undef Module32First
#undef Module32Next
#undef MODULEENTRY32
#endif

HINSTANCE GetModuleHandleExA_WOW64(HANDLE hProc, const char * szDll)
{
	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof(ME32);
	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hProc));
		
			if (hSnap != INVALID_HANDLE_VALUE)
				break;
		}
	}
		
	BOOL bRet = Module32First(hSnap, &ME32);
	while (bRet)
	{
		if (!_stricmp(ME32.szModule, szDll) && ME32.modBaseAddr < reinterpret_cast<BYTE*>(0x7FFFFFFF))
			break;
		bRet = Module32Next(hSnap, &ME32);
	}
	CloseHandle(hSnap);

	if (!bRet)
		return NULL;

	return ME32.hModule;
}

bool GetProcAddressA_WOW64(HANDLE hProc, HINSTANCE hDll, const char * szFunc, void * &pOut)
{
	BYTE * pBuffer = new BYTE[0x1000];
	if (!ReadProcessMemory(hProc, reinterpret_cast<void*>(hDll), pBuffer, 0x1000, nullptr))
	{
		delete[] pBuffer;

		return false;
	}

	auto * pNT = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<IMAGE_DOS_HEADER*>(pBuffer)->e_lfanew + pBuffer);
	auto * pDir = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto ExportSize = pDir->Size;
	auto DirRVA		= pDir->VirtualAddress;

	if (!ExportSize)
	{
		delete[] pBuffer;

		return false;
	}

	BYTE * pExpDirBuffer = new BYTE[ExportSize];
	auto * pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pExpDirBuffer);
	if (!ReadProcessMemory(hProc, reinterpret_cast<BYTE*>(hDll) + DirRVA, pExpDirBuffer, ExportSize, nullptr))
	{
		delete[] pExpDirBuffer;
		delete[] pBuffer;

		return false;
	}

	BYTE * pBase = pExpDirBuffer - DirRVA;

	auto Forwarded = [&](DWORD FuncRVA) -> BYTE*
	{
		char pFullExport[MAX_PATH]{ 0 };
		auto len_out = strlen(reinterpret_cast<char*>(pBase + FuncRVA));
		if (!len_out)
			return nullptr;

		memcpy(pFullExport, reinterpret_cast<char*>(pBase + FuncRVA), len_out);
		char * pFuncName = strchr(pFullExport, '.');
		*pFuncName++ = '\0';
		if (*pFuncName == '#')
			pFuncName = reinterpret_cast<char*>(LOWORD(atoi(++pFuncName)));

		void * pOut = nullptr;
		GetProcAddressA_WOW64(hProc, GetModuleHandleExA(hProc, pFullExport), pFuncName, pOut);
		return reinterpret_cast<BYTE*>(pOut);
	};

	if (reinterpret_cast<UINT_PTR>(szFunc) <= MAXWORD)
	{
		WORD Base		= LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szFunc) - Base;
		DWORD FuncRVA	= reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

		delete[] pExpDirBuffer;
		delete[] pBuffer;

		if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
		{
			pOut = (BYTE*)Forwarded(FuncRVA);
			return (pOut != nullptr);
		}
			
		pOut = reinterpret_cast<BYTE*>(hDll) + FuncRVA;
		
		return true;
	}

	DWORD max		= pExportDir->NumberOfNames - 1;
	DWORD min		= 0;
	WORD Ordinal	= 0;

	while (min <= max)
	{
		DWORD mid = (min + max) >> 1;

		DWORD CurrNameRVA	= reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfNames)[mid];
		char * szName		= reinterpret_cast<char*>(pBase + CurrNameRVA);

		int cmp = strcmp(szName, szFunc);
		if (cmp < 0)
			min = mid + 1;
		else if (cmp > 0)
			max = mid - 1;
		else 
		{
			Ordinal = reinterpret_cast<WORD*>(pBase + pExportDir->AddressOfNameOrdinals)[mid];
			break;
		}
	}
	
	if (!Ordinal)
	{
		delete[] pExpDirBuffer;
		delete[] pBuffer;

		return false;
	}
	
	DWORD FuncRVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

	delete[] pExpDirBuffer;
	delete[] pBuffer;

	if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
	{
		pOut = (BYTE*)Forwarded(FuncRVA);
		return (pOut != nullptr);
	}

	pOut = reinterpret_cast<BYTE*>(hDll) + FuncRVA;

	return true;
}

#endif