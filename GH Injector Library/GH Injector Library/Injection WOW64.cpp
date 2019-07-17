#ifdef _WIN64

#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

#pragma region Shellcodes

BYTE LoadLibraryShell_WOW64[]	= { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x85, 0xF6, 0x74, 0x1F, 0x8B, 0x4E, 0x04, 0x85, 0xC9, 0x74, 0x18, 0x6A,
	0x00, 0x6A, 0x00, 0x8D, 0x46, 0x08, 0x50, 0xFF, 0xD1, 0x89, 0x06, 0xC7, 0x46, 0x04, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x33, 0xC0,
	0x5E, 0x5D, 0xC2, 0x04, 0x00 };

BYTE LdrLoadDllShell_WOW64[]	= { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x85, 0xF6, 0x74, 0x29, 0x8B, 0x46, 0x04, 0x85, 0xC0, 0x74, 0x22, 0x8D, 
	0x4E, 0x14, 0x56, 0x89, 0x4E, 0x10, 0x8D, 0x4E, 0x0C, 0x51, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0xD0, 0x89, 0x46, 0x08, 0x8B, 0x06, 0xC7, 0x46, 0x04, 0x00,	
	0x00, 0x00, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x04, 0x00 
};

BYTE ManualMapShell_WOW64[]		= { 0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x08, 0x83, 0xEC, 0x28, 0x85, 0xD2, 0x0F, 0x84, 0x8B, 0x02, 0x00, 0x00, 0x83, 0x7A,
	0x04, 0x00, 0x0F, 0x84, 0x81, 0x02, 0x00, 0x00, 0x8B, 0x42, 0x08, 0x8B, 0x4A, 0x18, 0x53, 0x56, 0x57, 0x8B, 0x7A, 0x14, 0x89, 0x45, 0xE8, 0x89, 0x7D, 
	0xFC, 0x89, 0x4D, 0xE4, 0x8B, 0x5F, 0x3C, 0x03, 0xDF, 0x89, 0x5D, 0xEC, 0x8B, 0x43, 0x28, 0x03, 0xC7, 0x83, 0xBB, 0x84, 0x00, 0x00, 0x00, 0x00, 0x89, 
	0x45, 0xD8, 0x0F, 0x84, 0x0B, 0x01, 0x00, 0x00, 0x8B, 0x9B, 0x80, 0x00, 0x00, 0x00, 0x03, 0xDF, 0x89, 0x5D, 0xF8, 0x8B, 0x43, 0x0C, 0x85, 0xC0, 0x0F, 
	0x84, 0xF2, 0x00, 0x00, 0x00, 0x83, 0xE1, 0x10, 0x89, 0x4D, 0xF4, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x34, 0x38, 0x8B, 0x42, 0x04, 0x56, 
	0xFF, 0xD0, 0x83, 0x7D, 0xF4, 0x00, 0x8B, 0xC8, 0x8B, 0x03, 0x89, 0x45, 0xDC, 0x8B, 0x43, 0x10, 0x89, 0x4D, 0xF0, 0x89, 0x45, 0xE0, 0x8D, 0x1C, 0x38, 
	0x74, 0x36, 0x33, 0xC9, 0x38, 0x0E, 0x74, 0x07, 0x41, 0x80, 0x3C, 0x31, 0x00, 0x75, 0xF9, 0x8B, 0x75, 0xF8, 0x8B, 0x56, 0x0C, 0x03, 0xD7, 0x85, 0xC9, 
	0x74, 0x18, 0x8B, 0xFA, 0x33, 0xC0, 0x8B, 0xD1, 0xC1, 0xE9, 0x02, 0xF3, 0xAB, 0x8B, 0xCA, 0x83, 0xE1, 0x03, 0xF3, 0xAA, 0x8B, 0x7D, 0xFC, 0x8B, 0x45, 
	0xE0, 0x8B, 0x4D, 0xF0, 0xEB, 0x03, 0x8B, 0x75, 0xF8, 0x83, 0x3E, 0x00, 0x0F, 0x45, 0x45, 0xDC, 0x8D, 0x34, 0x38, 0x8B, 0x06, 0x85, 0xC0, 0x74, 0x63, 
	0x79, 0x17, 0x0F, 0xB7, 0xC0, 0x50, 0x51, 0xFF, 0x55, 0xE8, 0x83, 0x7D, 0xF4, 0x00, 0x89, 0x03, 0x74, 0x41, 0x33, 0xC0, 0x66, 0x89, 0x06, 0xEB, 0x3A, 
	0x83, 0xC0, 0x02, 0x03, 0xF8, 0x57, 0x51, 0xFF, 0x55, 0xE8, 0x83, 0x7D, 0xF4, 0x00, 0x89, 0x03, 0x74, 0x25, 0x33, 0xC9, 0x38, 0x0F, 0x74, 0x0B, 0x0F, 
	0x1F, 0x40, 0x00, 0x41, 0x80, 0x3C, 0x0F, 0x00, 0x75, 0xF9, 0x85, 0xC9, 0x74, 0x10, 0x8B, 0xD1, 0x33, 0xC0, 0xC1, 0xE9, 0x02, 0xF3, 0xAB, 0x8B, 0xCA, 
	0x83, 0xE1, 0x03, 0xF3, 0xAA, 0x8B, 0x7D, 0xFC, 0x8B, 0x46, 0x04, 0x83, 0xC6, 0x04, 0x8B, 0x4D, 0xF0, 0x83, 0xC3, 0x04, 0x85, 0xC0, 0x75, 0x9D, 0x8B, 
	0x5D, 0xF8, 0x8B, 0x55, 0x08, 0x83, 0xC3, 0x14, 0x89, 0x5D, 0xF8, 0x8B, 0x43, 0x0C, 0x85, 0xC0, 0x0F, 0x85, 0x1B, 0xFF, 0xFF, 0xFF, 0x8B, 0x5D, 0xEC, 
	0x83, 0xBB, 0xC4, 0x00, 0x00, 0x00, 0x00, 0x74, 0x21, 0x8B, 0x83, 0xC0, 0x00, 0x00, 0x00, 0x8B, 0x74, 0x38, 0x0C, 0x85, 0xF6, 0x74, 0x13, 0x90, 0x8B, 
	0x06, 0x85, 0xC0, 0x74, 0x0C, 0x6A, 0x00, 0x6A, 0x01, 0x57, 0xFF, 0xD0, 0x83, 0xC6, 0x04, 0x75, 0xEE, 0x6A, 0x00, 0x6A, 0x01, 0x57, 0xFF, 0x55, 0xD8, 
	0xF6, 0x45, 0xE4, 0x10, 0x0F, 0x84, 0xD6, 0x00, 0x00, 0x00, 0x8B, 0x8B, 0x84, 0x00, 0x00, 0x00, 0x8B, 0x75, 0xFC, 0x85, 0xC9, 0x74, 0x2C, 0x8B, 0xBB, 
	0x80, 0x00, 0x00, 0x00, 0x8B, 0xD1, 0xC1, 0xE9, 0x02, 0x03, 0xFE, 0x33, 0xC0, 0xF3, 0xAB, 0x8B, 0xCA, 0x83, 0xE1, 0x03, 0xF3, 0xAA, 0xC7, 0x83, 0x84, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x8B, 0xA4, 0x00, 0x00, 0x00, 0x85, 0xC9, 
	0x74, 0x2C, 0x8B, 0xBB, 0xA0, 0x00, 0x00, 0x00, 0x8B, 0xD1, 0xC1, 0xE9, 0x02, 0x03, 0xFE, 0x33, 0xC0, 0xF3, 0xAB, 0x8B, 0xCA, 0x83, 0xE1, 0x03, 0xF3, 
	0xAA, 0xC7, 0x83, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x83, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x83, 0xAC, 0x00, 
	0x00, 0x00, 0x89, 0x45, 0xD8, 0x85, 0xC0, 0x74, 0x57, 0x8B, 0x9B, 0xA8, 0x00, 0x00, 0x00, 0x03, 0xDE, 0x8B, 0x4B, 0x10, 0x85, 0xC9, 0x74, 0x1D, 0x8B, 
	0x53, 0x18, 0x85, 0xD2, 0x74, 0x16, 0x8D, 0x3C, 0x32, 0x33, 0xC0, 0x8B, 0xD1, 0xC1, 0xE9, 0x02, 0xF3, 0xAB, 0x8B, 0xCA, 0x83, 0xE1, 0x03, 0xF3, 0xAA, 
	0x8B, 0x45, 0xD8, 0x8B, 0xC8, 0x8B, 0xFB, 0x8B, 0xD1, 0x33, 0xC0, 0xC1, 0xE9, 0x02, 0xF3, 0xAB, 0x8B, 0xCA, 0x83, 0xE1, 0x03, 0xF3, 0xAA, 0x8B, 0x45, 
	0xEC, 0xC7, 0x80, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x80, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x7D, 0xFC, 0xF6, 
	0x45, 0xE4, 0x01, 0x74, 0x19, 0xC7, 0x07, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF7, 0xC7, 0x47, 0x04, 0x00, 0x00, 0x00, 0x00, 0xB9, 0xFE, 0x03, 0x00, 0x00, 
	0x83, 0xC7, 0x08, 0xF3, 0xA5, 0x8B, 0x45, 0x08, 0x8B, 0x75, 0xFC, 0x5F, 0x89, 0x30, 0x8B, 0xC6, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00, 0x33, 
	0xC0, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00
};

#pragma endregion

DWORD _LoadLibrary_WOW64	(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError);
DWORD _LdrLoadDll_WOW64		(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError);
DWORD _ManualMap_WOW64		(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError);

DWORD Cloaking_WOW64(HANDLE hProc, DWORD Flags, HINSTANCE hMod, DWORD & LastError);

DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, DWORD & LastError, HINSTANCE & hOut)
{
	if (Flags & INJ_LOAD_DLL_COPY)
	{
		size_t len_out = 0;
		StringCchLengthW(szDllFile, STRSAFE_MAX_CCH, &len_out);

		const wchar_t * pFileName = szDllFile;
		pFileName += len_out - 1;
		while (*(pFileName-- - 2) != '\\');
		
		wchar_t new_path[MAXPATH_IN_TCHAR]{ 0 };
		GetTempPathW(MAXPATH_IN_TCHAR, new_path);
		StringCchCatW(new_path, MAXPATH_IN_TCHAR, pFileName);

		CopyFileW(szDllFile, new_path, FALSE);

		szDllFile = new_path;
	}

	if (Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		wchar_t new_name[15]{ 0 };
		srand(GetTickCount() + rand() + Flags + LOWORD(hProc));

		for (UINT i = 0; i != 10; ++i)
		{
			auto val = rand() % 3;
			if (val == 0)
			{
				val = rand() % 10;
				new_name[i] = wchar_t('0' + val);
			}
			else if (val == 1)
			{
				val = rand() % 26;
				new_name[i] = wchar_t('A' + val);
			}
			else
			{
				val = rand() % 26;
				new_name[i] = wchar_t('a' + val);
			}
		}
		new_name[10] = '.';
		new_name[11] = 'd';
		new_name[12] = 'l';
		new_name[13] = 'l';
		new_name[14] = '\0';

		wchar_t OldFilePath[MAXPATH_IN_TCHAR]{ 0 };
		StringCchCopyW(OldFilePath, MAXPATH_IN_TCHAR, szDllFile);

		wchar_t * pFileName = const_cast<wchar_t*>(szDllFile);
		size_t len_out = 0;
		StringCchLengthW(szDllFile, STRSAFE_MAX_CCH, &len_out);
		pFileName += len_out;
		while (*(pFileName-- - 2) != '\\');

		memcpy(pFileName, new_name, 15 * sizeof(wchar_t));

		_wrename(OldFilePath, szDllFile);
	}

	DWORD Ret = 0;

	switch (im)
	{
		case IM_LoadLibrary:
			Ret = _LoadLibrary_WOW64(szDllFile, hProc, Method, Flags, hOut, LastError);
			break;

		case IM_LdrLoadDll:
			Ret = _LdrLoadDll_WOW64(szDllFile, hProc, Method, Flags, hOut, LastError);
			break;

		case IM_ManualMap:
			Ret = _ManualMap_WOW64(szDllFile, hProc, Method, Flags, hOut, LastError);
	}

	if (Ret == INJ_ERR_SUCCESS && hOut && im != IM_ManualMap)
		Ret = Cloaking_WOW64(hProc, Flags, hOut, LastError);
	
	return Ret;
}

DWORD _LoadLibrary_WOW64(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	LOAD_LIBRARY_DATA_WOW64 data{ 0 };
	StringCchCopyW(data.szDll, sizeof(data.szDll) / sizeof(wchar_t), szDllFile);

	void * pLoadLibraryExW = nullptr;
	char sz_LoadLibName[] = "LoadLibraryExW";

	if (!GetProcAddressA_WOW64(hProc, GetModuleHandleExA_WOW64(hProc, "kernel32.dll"), sz_LoadLibName, pLoadLibraryExW))
	{
		LastError = GetLastError();
		return INJ_ERR_REMOTEFUNC_MISSING;
	}
	
	data.pLoadLibraryExW = (DWORD)(UINT_PTR)pLoadLibraryExW;

	BYTE * pArg = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(LOAD_LIBRARY_DATA_WOW64) + sizeof(LoadLibraryShell_WOW64) + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pArg)
	{
		LastError = GetLastError();
		return INJ_ERR_OUT_OF_MEMORY;
	}

	if (!WriteProcessMemory(hProc, pArg, &data, sizeof(LOAD_LIBRARY_DATA_WOW64), nullptr))
	{
		LastError = GetLastError();

		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	auto * pShell = ReCa<BYTE*>(ALIGN_UP(ReCa<UINT_PTR>(pArg + sizeof(LOAD_LIBRARY_DATA_WOW64)), 0x10));
	if (!WriteProcessMemory(hProc, pShell, LoadLibraryShell_WOW64, sizeof(LoadLibraryShell_WOW64), nullptr))
	{
		LastError = GetLastError();

		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD dwRet = StartRoutine_WOW64(hProc, pShell, pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, CC_STDCALL, LastError, hOut);
	
	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
	
	return dwRet;
}

DWORD _LdrLoadDll_WOW64(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	size_t size_out = 0;

	LDR_LOAD_DLL_DATA_WOW64 data{ 0 };
	data.pModuleFileName.MaxLength = sizeof(data.Data);
	StringCbLengthW(szDllFile, data.pModuleFileName.MaxLength, &size_out);
	StringCbCopyW(ReCa<wchar_t*>(data.Data), data.pModuleFileName.MaxLength, szDllFile);
	data.pModuleFileName.Length = (WORD)size_out;

	void * pLdrLoadDll = nullptr;
	if (!GetProcAddressA_WOW64(hProc, GetModuleHandleExA_WOW64(hProc, "ntdll.dll"), "LdrLoadDll", pLdrLoadDll))
	{
		LastError = GetLastError();
		return INJ_ERR_LDRLOADDLL_MISSING;
	}
	
	data.pLdrLoadDll = (DWORD)(UINT_PTR)pLdrLoadDll;

	BYTE * pArg = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(LDR_LOAD_DLL_DATA_WOW64) + sizeof(LdrLoadDllShell_WOW64) + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pArg)
	{
		LastError = GetLastError();
		return INJ_ERR_CANT_ALLOC_MEM;
	}

	if (!WriteProcessMemory(hProc, pArg, &data, sizeof(LDR_LOAD_DLL_DATA_WOW64), nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}
	
	auto * pShell = ReCa<BYTE*>(ALIGN_UP(ReCa<UINT_PTR>(pArg + sizeof(LDR_LOAD_DLL_DATA_WOW64)), 0x10));
	if (!WriteProcessMemory(hProc, pShell, LdrLoadDllShell_WOW64, sizeof(LdrLoadDllShell_WOW64), nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}
	
	DWORD dwRet = StartRoutine_WOW64(hProc, pShell, pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, CC_STDCALL, LastError, hOut);
	
	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

	return dwRet;
}

DWORD _ManualMap_WOW64(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	BYTE *						pSrcData		= nullptr;
	IMAGE_NT_HEADERS32 *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER32 *	pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *			pOldFileHeader	= nullptr;
	BYTE *						pLocalBase		= nullptr;
	BYTE *						pAllocBase		= nullptr;
	BYTE *						pTargetBase		= nullptr;
	BYTE *						pArg			= nullptr;
	BYTE *						pFunc			= nullptr;

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	auto FileSize = File.tellg();

	pSrcData = new BYTE[static_cast<size_t>(FileSize)];

	if (!pSrcData)
	{
		File.close();
		return INJ_ERR_OUT_OF_MEMORY;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pSrcData), FileSize);
	File.close();

	pOldNtHeader	= ReCa<IMAGE_NT_HEADERS32*>(pSrcData + ReCa<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader	= &pOldNtHeader->OptionalHeader;
	pOldFileHeader	= &pOldNtHeader->FileHeader;

	DWORD ShiftOffset = 0;
	if (Flags & INJ_SHIFT_MODULE)
	{
		srand(GetTickCount() + pOldOptHeader->SizeOfImage);
		ShiftOffset = rand() % 0x1000 + 0x100;
	}

	auto AllocSize = ShiftOffset + pOldOptHeader->SizeOfImage + sizeof(MANUAL_MAPPING_DATA_WOW64) + sizeof(ManualMapShell_WOW64) + 0x18;

	pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hProc, (void*)(UINT_PTR)pOldOptHeader->ImageBase, AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pAllocBase)
		pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	
	if (!pAllocBase)
	{
		LastError = GetLastError();

		delete[] pSrcData;

		return INJ_ERR_CANT_ALLOC_MEM;
	}
	
	pLocalBase = ReCa<BYTE*>(VirtualAlloc(nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pLocalBase)
	{
		LastError = GetLastError();

		delete[] pSrcData;
		VirtualFreeEx(hProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_OUT_OF_MEMORY;
	}

	if (ShiftOffset)
	{
		DWORD * pJunk = new DWORD[ShiftOffset / sizeof(DWORD) + 1];
		DWORD SuperJunk = GetTickCount();

		for (UINT i = 0; i < ShiftOffset / sizeof(DWORD) + 1; ++i)
		{
			pJunk[i] = SuperJunk;
			SuperJunk ^= (i << (i % 32));
			SuperJunk -= 0x11111111;
		}

		WriteProcessMemory(hProc, pAllocBase, pJunk, ShiftOffset, nullptr);

		delete[] pJunk;
	}

	pTargetBase = ReCa<BYTE*>(ALIGN_IMAGE_BASE_X86	(ReCa<UINT_PTR>(pAllocBase)		+ ShiftOffset));
	pArg		= ReCa<BYTE*>(ALIGN_UP				(ReCa<UINT_PTR>(pTargetBase)	+ pOldOptHeader->SizeOfImage, 0x08));
	pFunc		= ReCa<BYTE*>(ALIGN_UP				(ReCa<UINT_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA), 0x08));
	
	memset(pLocalBase, 0, pOldOptHeader->SizeOfImage);
	memcpy(pLocalBase, pSrcData, 0x1000);
	
	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i < pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		if (pSectionHeader->SizeOfRawData)
			memcpy(pLocalBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);

	BYTE * LocationDelta = (BYTE*)(UINT_PTR)((DWORD)(UINT_PTR)pTargetBase - pOldOptHeader->ImageBase);

	if (LocationDelta)
	{
		if (!pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return NULL;

		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(pLocalBase + pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			WORD * pRelativeInfo = ReCa<WORD*>(pRelocData + 1);
			for (UINT i = 0; i < ((pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); ++i, ++pRelativeInfo)
			{
				if(RELOC_FLAG86(*pRelativeInfo))
				{
					DWORD * pPatch = ReCa<DWORD*>(pLocalBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += ReCa<UINT_PTR>(LocationDelta) & 0xFFFFFFFF;
				}
			}
			pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(ReCa<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	auto LoadFunctionPointer = [=](HINSTANCE hLib, const char * szFunc, void * &pOut)
	{
		if (!GetProcAddressA_WOW64(hProc, hLib, szFunc, pOut))
		{
			delete[] pSrcData;
			VirtualFree(pLocalBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pAllocBase, 0, MEM_RELEASE);

			return false;
		}

		return true;
	};

	HINSTANCE hK32 = GetModuleHandleExA_WOW64(hProc, "kernel32.dll");

	void * pLoadLibraryA = nullptr;
	if (!LoadFunctionPointer(hK32, "LoadLibraryA", pLoadLibraryA))
		return INJ_ERR_REMOTEFUNC_MISSING;
	
	void * pGetProcAddress = nullptr;
	if (!LoadFunctionPointer(hK32, "GetProcAddress", pGetProcAddress))
		return INJ_ERR_REMOTEFUNC_MISSING;

	void * pVirtualAlloc = nullptr;
	if (!LoadFunctionPointer(hK32, "VirtualAlloc", pVirtualAlloc))
		return INJ_ERR_REMOTEFUNC_MISSING;
	
	void * pVirtualFree = nullptr;
	if (!LoadFunctionPointer(hK32, "VirtualFree", pVirtualFree))
		return INJ_ERR_REMOTEFUNC_MISSING;
	
	MANUAL_MAPPING_DATA_WOW64 data{ 0 };
	data.pLoadLibraryA		= (DWORD)(UINT_PTR)pLoadLibraryA;
	data.pGetProcAddress	= (DWORD)(UINT_PTR)pGetProcAddress;
	data.pVirtualAlloc		= (DWORD)(UINT_PTR)pVirtualAlloc;
	data.pVirtualFree		= (DWORD)(UINT_PTR)pVirtualFree;
	data.pModuleBase		= (DWORD)(UINT_PTR)pTargetBase;
	data.Flags				= Flags;
	
	BOOL bRet1 = WriteProcessMemory(hProc, pTargetBase, pLocalBase, pOldOptHeader->SizeOfImage, nullptr);
	BOOL bRet2 = WriteProcessMemory(hProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr);
	BOOL bRet3 = WriteProcessMemory(hProc, pFunc, ManualMapShell_WOW64, sizeof(ManualMapShell_WOW64), nullptr);

	if (!bRet1 || !bRet2 || !bRet3)
	{
		LastError = GetLastError();

		delete[] pSrcData;
		VirtualFree(pLocalBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	delete[] pSrcData;
	VirtualFree(pLocalBase, 0, MEM_RELEASE);

	DWORD dwRet = StartRoutine_WOW64(hProc, pFunc, pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, CC_STDCALL, LastError, hOut);

	if (Method != LM_QueueUserAPC)
	{
		auto zero_size		= pAllocBase + AllocSize - pArg;
		BYTE * zero_bytes	= new BYTE[zero_size];
		memset(zero_bytes, 0, zero_size);

		WriteProcessMemory(hProc, pArg, zero_bytes, zero_size, nullptr);

		delete[] zero_bytes;
	}

	if (Flags & INJ_FAKE_HEADER)
	{
		BYTE buffer[0x1000];
		ReadProcessMemory(hProc, (void*)hK32, buffer, 0x1000, nullptr);
		WriteProcessMemory(hProc, pTargetBase, buffer, 0x1000, nullptr);
	}

	return dwRet;
}

DWORD Cloaking_WOW64(HANDLE hProc, DWORD Flags, HINSTANCE hMod, DWORD & LastError)
{
	if (!Flags)
		return INJ_ERR_SUCCESS;

	if (Flags & INJ_ERASE_HEADER)
	{
		BYTE Buffer[0x1000]{ 0 };
		DWORD dwOld = 0; 
		BOOL bRet = VirtualProtectEx(hProc, hMod, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
		if (!bRet)
		{
			LastError = GetLastError();
			return INJ_ERR_VPE_FAIL;
		}

		bRet = WriteProcessMemory(hProc, hMod, Buffer, 0x1000, nullptr);
		if (!bRet)
		{
			LastError = GetLastError();
			return INJ_ERR_WPM_FAIL;
		}
	}
	else if (Flags & INJ_FAKE_HEADER)
	{
		void * pK32 = ReCa<void*>(GetModuleHandleExA_WOW64(hProc, "kernel32.dll"));
		DWORD dwOld = 0;

		BYTE buffer[0x1000];
		BOOL bRet = ReadProcessMemory(hProc, pK32, buffer, 0x1000, nullptr);
		if (!bRet)
		{
			LastError = GetLastError();
			return INJ_ERR_RPM_FAIL;
		}

		bRet = VirtualProtectEx(hProc, hMod, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
		if (!bRet)
		{
			LastError = GetLastError();
			return INJ_ERR_VPE_FAIL;
		}

		bRet = WriteProcessMemory(hProc, hMod, pK32, 0x1000, nullptr);
		if (!bRet)
		{
			LastError = GetLastError();
			return INJ_ERR_WPM_FAIL;
		}

		bRet = VirtualProtectEx(hProc, hMod, 0x1000, dwOld, &dwOld);
		if (!bRet)
		{
			LastError = GetLastError();
			return INJ_ERR_VPE_FAIL;
		}
	}

	if (Flags & INJ_UNLINK_FROM_PEB)
	{
		ProcessInfo ProcInfo;
		ProcInfo.SetProcess(hProc);

		PEB32 * ppeb = ReCa<PEB32*>(ProcInfo.GetPEB());

		PEB32 peb{ 0 };
		if (!ReadProcessMemory(hProc, ReCa<BYTE*>(ppeb) + 0x1000, &peb, sizeof(PEB32), nullptr))
		{
			LastError = GetLastError();
			return INJ_ERR_CANT_ACCESS_PEB;
		}

		PEB_LDR_DATA32 ldrdata{ 0 };
		if (!ReadProcessMemory(hProc, (void*)(UINT_PTR)peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA32), nullptr))
		{
			LastError = GetLastError();
			return INJ_ERR_CANT_ACCESS_PEB_LDR;
		}

		LIST_ENTRY32 * pCurrentEntry	= (LIST_ENTRY32*)(UINT_PTR)ldrdata.InLoadOrderModuleListHead.Flink;
		LIST_ENTRY32 * pLastEntry		= (LIST_ENTRY32*)(UINT_PTR)ldrdata.InLoadOrderModuleListHead.Blink;

		while (true)
		{
			LDR_DATA_TABLE_ENTRY32 CurrentEntry;
			ReadProcessMemory(hProc, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY32), nullptr);

			if (CurrentEntry.DllBase == (DWORD)(UINT_PTR)hMod)
			{
				auto Unlink = [=](LIST_ENTRY32 entry)
				{
					LIST_ENTRY32 list;
					ReadProcessMemory(hProc, (void*)(UINT_PTR)entry.Flink, &list, sizeof(LIST_ENTRY32), nullptr);
					list.Blink = entry.Blink;
					WriteProcessMemory(hProc, (void*)(UINT_PTR)entry.Flink, &list, sizeof(LIST_ENTRY32), nullptr);

					ReadProcessMemory(hProc, (void*)(UINT_PTR)entry.Blink, &list, sizeof(LIST_ENTRY32), nullptr);
					list.Flink = entry.Flink;
					WriteProcessMemory(hProc, (void*)(UINT_PTR)entry.Blink, &list, sizeof(LIST_ENTRY32), nullptr);
				};

				Unlink(CurrentEntry.InLoadOrder);
				Unlink(CurrentEntry.InMemoryOrder);
				Unlink(CurrentEntry.InInitOrder);

				BYTE Buffer[MAX_PATH * 4]{ 0 };
				WriteProcessMemory(hProc, (void*)(UINT_PTR)CurrentEntry.BaseDllName.szBuffer, Buffer, CurrentEntry.BaseDllName.MaxLength, nullptr);
				WriteProcessMemory(hProc, (void*)(UINT_PTR)CurrentEntry.FullDllName.szBuffer, Buffer, CurrentEntry.FullDllName.MaxLength, nullptr);
				WriteProcessMemory(hProc, pCurrentEntry, Buffer, sizeof(LDR_DATA_TABLE_ENTRY32), nullptr);

				return INJ_ERR_SUCCESS;
			}

			if (pCurrentEntry == pLastEntry)
			{
				return INJ_ERR_CANT_FIND_MOD_PEB;
			}

			pCurrentEntry = (LIST_ENTRY32*)(UINT_PTR)CurrentEntry.InLoadOrder.Flink;
		}
	}
	
	return INJ_ERR_SUCCESS;
}

#endif