#include "Import Handler.h"

BYTE * GetProcAddressA(HINSTANCE hDll, char * szFunc);

bool GetImportA(HANDLE hProc, char * szDll, char * szFunc, void * &pOut)
{
	HINSTANCE hDll = LoadLibraryA(szDll);
	if (!hDll)
		return false;

	BYTE * pFunc = GetProcAddressA(hDll, szFunc);
	if (!pFunc)
		return false;
	
	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProc));
	BOOL bRet = Module32First(hSnap, &ME32);
	while (bRet)
	{
		if (!_stricmp(ME32.szModule, szDll))
			break;

		bRet = Module32Next(hSnap, &ME32);
	}
	CloseHandle(hSnap);

	if (!bRet)
		return false;

	auto delta = reinterpret_cast<BYTE*>(ME32.hModule) - reinterpret_cast<BYTE*>(hDll);
	pOut = pFunc + delta;
	
	return true;
}

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
		WORD Base		= LOWORD(pExportDir->Base - 1);
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

	DWORD FuncRVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

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