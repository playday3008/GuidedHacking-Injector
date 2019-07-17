#include "Import Handler.h"
#pragma comment(lib, "Psapi.lib")

BYTE * GetProcAddressA(HINSTANCE hDll, char * szFunc)
{
	if (!hDll)
		return nullptr;

	BYTE * pBase		= reinterpret_cast<BYTE*>(hDll);	
	auto * pNT			= reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew);
	auto * pDirectory	= &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto * pExportDir	= reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBase + pDirectory->VirtualAddress);
	auto ExportSize		= pDirectory->Size;
	DWORD DirRVA		= pDirectory->VirtualAddress;

	if (!ExportSize)
		return nullptr;

	if (reinterpret_cast<UINT_PTR>(szFunc) <= MAXWORD)
	{
		WORD Base = LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szFunc) - Base;
		DWORD FuncRVA	= reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

		if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
		{
			char pFullExport[MAX_PATH]{ 0 };
			auto Len = strlen(reinterpret_cast<char*>(pBase + FuncRVA));
			if (!Len)
				return nullptr;

			memcpy(pFullExport, reinterpret_cast<char*>(pBase + FuncRVA), Len);
			char * pFuncName = strchr(pFullExport, '.');
			*pFuncName++ = '\0';
			if (*pFuncName == '#')
				pFuncName = reinterpret_cast<char*>(LOWORD(atoi(++pFuncName)));

			HINSTANCE hLib = LoadLibraryA(pFullExport);
			if (hLib == reinterpret_cast<HINSTANCE>(hDll) && !strcmp(pFuncName, szFunc))
			{
				return nullptr;
			}

			return GetProcAddressA(hLib, pFuncName);
		}
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
		return nullptr;

	DWORD FuncRVA	= reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

	if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
	{
		char pFullExport[MAX_PATH]{ 0 };
		auto Len = strlen(reinterpret_cast<char*>(pBase + FuncRVA));
		if (!Len)
			return nullptr;

		memcpy(pFullExport, reinterpret_cast<char*>(pBase + FuncRVA), Len);
		char * pFuncName = strchr(pFullExport, '.');
		*pFuncName++ = '\0';
		if (*pFuncName == '#')
			pFuncName = reinterpret_cast<char*>(LOWORD(atoi(++pFuncName)));

		HINSTANCE hLib = LoadLibraryA(pFullExport);
		if (hLib == reinterpret_cast<HINSTANCE>(hDll) && !strcmp(pFuncName, szFunc))
		{
			return nullptr;
		}

		return GetProcAddressA(hLib, pFuncName);
	}

	return pBase + FuncRVA;
}

bool GetImportA(HANDLE hProc, char * szDll, char * szFunc, void * &pOut)
{
	HINSTANCE hDll = GetModuleHandleA(szDll);
	if (!hDll)
		return false;

	void * pFunc1 = GetProcAddress(hDll, szFunc);
	void * pFunc2 = GetProcAddressA(hDll, szFunc);

	if (!pFunc1 && !pFunc2)
	{
		pOut = nullptr;
		return false;
	}
	else if (!pFunc1)
	{
		pOut = pFunc2;
		return true;
	}
	else if(!pFunc2)
	{
		pOut = pFunc1;
		return true;
	}

	if (pFunc1 != pFunc2)
	{
		BYTE * pBase1 = (BYTE*)pFunc1;
		BYTE * pBase2 = (BYTE*)pFunc2;

		HINSTANCE hNew = NULL;
		char pBuffer[MAX_PATH]{ 0 };

		if (AddressToModuleBase(GetCurrentProcess(), pBase1))
		{
			hNew = reinterpret_cast<HINSTANCE>(pBase1);
			if (GetModuleBaseNameA(hProc, hNew, pBuffer, MAX_PATH))
			{
				pOut = pFunc1;
				return true;
			}
		}
		
		if (AddressToModuleBase(GetCurrentProcess(), pBase2))
		{
			hNew = reinterpret_cast<HINSTANCE>(pBase2);
			if (GetModuleBaseNameA(hProc, hNew, pBuffer, MAX_PATH))
			{
				pOut = pFunc2;
				return true;
			}
		}
		
		pOut = nullptr;
		return false;
	}
	
	pOut = pFunc1;
	
	return true;
}

bool AddressToModuleBase(HANDLE hProc, BYTE * &pAddress)
{
	auto p_NtQueryVirtualMemory = reinterpret_cast<f_NtQueryVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory"));

	SECTION_INFO section_info;
	NTSTATUS ntRet = p_NtQueryVirtualMemory(hProc, pAddress, MemoryMappedFilenameInformation, &section_info, sizeof(section_info), nullptr);
	if (NT_FAIL(ntRet))
		return false;	

	wchar_t * pDeviceName	= section_info.szData;
	wchar_t * pFilePath		= pDeviceName;
	
	while (*(pFilePath++) != '\\');
	while (*(pFilePath++) != '\\');
	while (*(pFilePath++) != '\\');
	*(pFilePath - 1) = 0;

	wchar_t * DriveLetters = new wchar_t[MAX_PATH + 1];
	auto size = GetLogicalDriveStringsW(MAX_PATH, DriveLetters);
	if (size > MAX_PATH)
	{
		delete[] DriveLetters;
		DriveLetters = new wchar_t[size + 1];
		size = GetLogicalDriveStringsW(size, DriveLetters);
	}

	for (DWORD i = 0; i != size / 4; ++i)
	{
		DriveLetters[i * 4 + 2] = 0;
		wchar_t Buffer[64]{ 0 };

		QueryDosDeviceW(&DriveLetters[i * 4], Buffer, sizeof(Buffer));
		if (!wcscmp(Buffer, pDeviceName))
		{
			pFilePath -= 3;
			pFilePath[2] = '\\';
			pFilePath[1] = ':';
			pFilePath[0] = DriveLetters[i * 4];

			delete[] DriveLetters;

			BYTE * Ret = reinterpret_cast<BYTE*>(GetModuleHandleW(pFilePath));
			if (!Ret)
				return false;

			pAddress = Ret;
			return true;
		}
	}
	
	delete[] DriveLetters;

	return false;
}