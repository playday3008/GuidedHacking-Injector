#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

DWORD LastError = INJ_ERR_SUCCESS;
DWORD g_TID	= 0;
HWND g_hWnd	= NULL;

DWORD LoadLibraryStub	(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags);
DWORD ManualMap			(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags);
DWORD LdrLoadDllStub	(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags);
DWORD Cloaking			(const char * szDllFile, HANDLE hProc, DWORD Flags);

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);

void __stdcall LoadLibraryShell (LOAD_LIBRARY_DATA * pData);
void __stdcall LdrLoadDllShell	(LDR_LOAD_DLL_DATA * pData);
void __stdcall ImportTlsExecute	(MANUAL_MAPPING_DATA * pData);

HANDLE StartRoutine(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool HideFromDebugger = false, bool Fastcall = true);
PEB * GetPEB(HANDLE hProc);

DWORD InjectDLL(const char * szDllFile, HANDLE hProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, DWORD * ErrorCode)
{	
	if (!szDllFile)
		return INJ_ERR_FILE_DOESNT_EXIST;

	char szPathBuffer[MAX_PATH]{ 0 };
	if (szDllFile[1] != ':')
	{
		GetFullPathNameA(szDllFile, MAX_PATH, szPathBuffer, nullptr);
		szDllFile = szPathBuffer;
	}

	DWORD Ret = 0;

	switch (im)
	{
		case IM_LoadLibrary:
			Ret = LoadLibraryStub(szDllFile, hProc, Method, Flags);
			break;

		case IM_LdrLoadDll:
			Ret = LdrLoadDllStub(szDllFile, hProc, Method, Flags);
			break;

		case IM_ManualMap:
			Ret = ManualMap(szDllFile, hProc, Method, Flags);
	}

	if (Ret == INJ_ERR_SUCCESS && im != IM_ManualMap)
		Ret = Cloaking(szDllFile, hProc, Flags);

	if (ErrorCode)
		*ErrorCode = LastError;

	return Ret;
}

DWORD LoadLibraryStub(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags)
{
	if (!hProc)
		return INJ_ERR_INVALID_PROC_HANDLE;

	if (!FileExistsA(szDllFile))
	{
		return INJ_ERR_FILE_DOESNT_EXIST;
	}

	LOAD_LIBRARY_DATA data{ 0 };
	size_t len = _strlenA(szDllFile);
	memcpy(data.szDll, szDllFile, len);

	void * pLoadLibraryA = nullptr;
	if (!GetImportA(hProc, "kernel32.dll", "LoadLibraryA", pLoadLibraryA))
	{
		LastError = GetLastError();
		return INJ_ERR_LDRLOADDLL_MISSING;
	}
	
	data.pLoadLibraryA = ReCa<f_LoadLibraryA>(pLoadLibraryA);

	BYTE * pArg = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(LOAD_LIBRARY_DATA) + 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pArg)
	{
		LastError = GetLastError();
		return INJ_ERR_OUT_OF_MEMORY;
	}

	if (!WriteProcessMemory(hProc, pArg, &data, sizeof(LOAD_LIBRARY_DATA), nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hProc, pArg + sizeof(LOAD_LIBRARY_DATA), LoadLibraryShell, 0x100, nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	DWORD dwExitCode = 0;
	HANDLE hThread = StartRoutine(hProc, pArg + sizeof(LOAD_LIBRARY_DATA), pArg, Method, (Flags & INJ_HIDE_THREAD_FROM_DEBUGGER) != 0, false);
	if (!hThread)
	{
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_CANT_CREATE_THREAD;
	}
	else if (Method == LM_NtCreateThreadEx)
	{
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, &dwExitCode);
		CloseHandle(hThread);
	}
	else
		dwExitCode = 1;

	VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

	if (!dwExitCode)
	{
		LastError = INJ_ERR_ADV_UNKNOWN;
		return INJ_ERR_UNKNOWN;
	}

	return INJ_ERR_SUCCESS;
}

DWORD LdrLoadDllStub(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags)
{
	if (!hProc)
		return INJ_ERR_INVALID_PROC_HANDLE;

	if (!szDllFile)
		return INJ_ERR_FILE_DOESNT_EXIST;

	char szPathBuffer[MAX_PATH]{ 0 };
	if (szDllFile[1] != ':')
	{
		GetFullPathNameA(szDllFile, MAX_PATH, szPathBuffer, nullptr);
		szDllFile = szPathBuffer;
	}

	if (!FileExistsA(szDllFile))
	{
		return INJ_ERR_FILE_DOESNT_EXIST;
	}

	LDR_LOAD_DLL_DATA data{ 0 };
	data.pModuleFileName.szBuffer	= ReCa<wchar_t*>(data.Data);
	data.pModuleFileName.MaxLength	= MAX_PATH * 2;

	size_t len = _strlenA(szDllFile);
	mbstowcs_s(&len, data.pModuleFileName.szBuffer, len + 1, szDllFile, len);
	data.pModuleFileName.Length = (WORD)(len * 2) - 2;

	void * pLdrLoadDll = nullptr;
	if (!GetImportA(hProc, "ntdll.dll", "LdrLoadDll", pLdrLoadDll))
	{
		LastError = GetLastError();
		return INJ_ERR_LDRLOADDLL_MISSING;
	}
	
	data.pLdrLoadDll = ReCa<f_LdrLoadDll>(pLdrLoadDll);

	BYTE * pArg = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(LDR_LOAD_DLL_DATA) + 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pArg)
	{
		LastError = GetLastError();
		return INJ_ERR_CANT_ALLOC_MEM;
	}

	if (!WriteProcessMemory(hProc, pArg, &data, sizeof(LDR_LOAD_DLL_DATA), nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hProc,pArg + sizeof(LDR_LOAD_DLL_DATA), LdrLoadDllShell, 0x100, nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	HANDLE hThread = StartRoutine(hProc, pArg + sizeof(LDR_LOAD_DLL_DATA), pArg, Method, (Flags & INJ_HIDE_THREAD_FROM_DEBUGGER) != 0, false);
	if (!hThread)
	{
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_CANT_CREATE_THREAD;
	}
	else if (Method == LM_NtCreateThreadEx)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

	return INJ_ERR_SUCCESS;
}

DWORD ManualMap(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags)
{
	if (!hProc)
		return INJ_ERR_INVALID_PROC_HANDLE;

	if (!szDllFile)
		return INJ_ERR_FILE_DOESNT_EXIST;

	char szPathBuffer[MAX_PATH]{ 0 };
	if (szDllFile[1] != ':')
	{
		GetFullPathNameA(szDllFile, MAX_PATH, szPathBuffer, nullptr);
		szDllFile = szPathBuffer;
	}

	if (!FileExistsA(szDllFile))
	{
		return INJ_ERR_FILE_DOESNT_EXIST;
	}

	BYTE *					pSrcData		= nullptr;
	IMAGE_NT_HEADERS *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *		pOldFileHeader	= nullptr;
	BYTE *					pLocalBase		= nullptr;
	BYTE *					pTargetBase		= nullptr;

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	auto FileSize = File.tellg();
	if (FileSize <= 0x1000)
	{
		File.close();
		return INJ_ERR_INVALID_FILE;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];

	if (!pSrcData)
	{
		File.close();
		return INJ_ERR_OUT_OF_MEMORY;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pSrcData), FileSize);
	File.close();

	if (ReCa<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
	{
		delete[] pSrcData;
		return INJ_ERR_INVALID_FILE;
	}

	pOldNtHeader	= ReCa<IMAGE_NT_HEADERS*>(pSrcData + ReCa<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader	= &pOldNtHeader->OptionalHeader;
	pOldFileHeader	= &pOldNtHeader->FileHeader;

	#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		delete[] pSrcData;
		return INJ_ERR_NO_X64FILE;
	}
	#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		delete[] pSrcData;
		return INJ_ERR_NO_X86FILE;
	}
	#endif

	DWORD ShiftOffset = 0;
	if (Flags & INJ_SHIFT_MODULE)
	{
		srand(GetTickCount());
		ShiftOffset = rand() % 0x1000 + 0x100;
		ShiftOffset &= 0xFF80;
	}

	pTargetBase = ReCa<BYTE*>(VirtualAllocEx(hProc, ReCa<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage + ShiftOffset, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
		pTargetBase = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage + ShiftOffset, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pTargetBase)
	{
		delete[] pSrcData;
		LastError = GetLastError();
		return INJ_ERR_CANT_ALLOC_MEM;
	}
	
	pLocalBase = ReCa<BYTE*>(VirtualAlloc(nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pLocalBase)
	{
		delete[] pSrcData;
		LastError = GetLastError();
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
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

		WriteProcessMemory(hProc, pTargetBase, pJunk, ShiftOffset, nullptr);

		pTargetBase += ShiftOffset;

		delete[] pJunk;
	}

	memset(pLocalBase, 0, pOldOptHeader->SizeOfImage);
	memcpy(pLocalBase, pSrcData, 0x1000);
	
	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i < pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		if (pSectionHeader->SizeOfRawData)
			memcpy(pLocalBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);

	delete[] pSrcData;

	void * pLoadLibraryA = nullptr;
	if (!GetImportA(hProc, "kernel32.dll", "LoadLibraryA", pLoadLibraryA))
	{
		VirtualFree(pLocalBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pTargetBase - ShiftOffset, 0, MEM_RELEASE);
		return INJ_ERR_LOADLIBRARY_MISSING;
	}

	ReCa<MANUAL_MAPPING_DATA*>(pLocalBase)->pLoadLibraryA	= ReCa<f_LoadLibraryA>(pLoadLibraryA);
	ReCa<MANUAL_MAPPING_DATA*>(pLocalBase)->pGetProcAddress = ReCa<f_GetProcAddress>(GetProcAddress);
	ReCa<MANUAL_MAPPING_DATA*>(pLocalBase)->Flags			= Flags;

	BOOL Ret = WriteProcessMemory(hProc, pTargetBase, pLocalBase, pOldOptHeader->SizeOfImage, nullptr);
	if (!Ret)
	{
		LastError = GetLastError();
		VirtualFree(pLocalBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pTargetBase - ShiftOffset, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}
	
	VirtualFree(pLocalBase, 0, MEM_RELEASE);

	ULONG_PTR FuncSize = 0x1000;
	void * pFunc = VirtualAllocEx(hProc, nullptr, FuncSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pFunc)
	{
		LastError = GetLastError();
		return INJ_ERR_CANT_ALLOC_MEM;
	}

	if (!WriteProcessMemory(hProc, pFunc, ImportTlsExecute, FuncSize, nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pFunc, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}
	
	HANDLE hThread = StartRoutine(hProc, pFunc, pTargetBase, Method, (Flags & INJ_HIDE_THREAD_FROM_DEBUGGER) != 0, false);

	if (!hThread)
	{
		VirtualFreeEx(hProc, pFunc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return INJ_ERR_CANT_CREATE_THREAD;
	}
	else if (Method == LM_NtCreateThreadEx)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	VirtualFreeEx(hProc, pFunc, 0, MEM_RELEASE);

	if (Flags & INJ_FAKE_HEADER)
	{
		void * pK32 = ReCa<void*>(GetModuleHandleA("kernel32.dll"));
		WriteProcessMemory(hProc, pTargetBase, pK32, 0x1000, nullptr);
	}

	return INJ_ERR_SUCCESS;
}

DWORD Cloaking(const char * szDllFile, HANDLE hProc, DWORD Flags)
{
	if (!Flags)
		return INJ_ERR_SUCCESS;

	if (Flags > INJ_MAX_FLAGS)
		return INJ_ERR_INVALID_FLAGS;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProc));
	if (!hSnap)
	{
		LastError = GetLastError();
		return INJ_ERR_TH32_FAIL;
	}

	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof(MODULEENTRY32);

	HINSTANCE hMod = 0;

	BOOL Ret = Module32First(hSnap, &ME32);
	while (Ret)
	{
		char Buffer[MAX_PATH]{ 0 };
		GetModuleFileNameExA(hProc, ReCa<HINSTANCE>(ME32.modBaseAddr), Buffer, MAX_PATH);
		if (Buffer[3] == szDllFile[3] && !lstrcmpA(szDllFile, Buffer))
		{
			hMod = ME32.hModule;
			break;
		}
		Ret = Module32Next(hSnap, &ME32);
	}
	CloseHandle(hSnap);

	if (!Ret && !hMod)
		return INJ_ERR_CANT_FIND_MOD;

	
	if (Flags & INJ_ERASE_HEADER)
	{
		BYTE Buffer[0x1000]{ 0 };
		DWORD dwOld = 0; BOOL bRet = VirtualProtectEx(hProc, hMod, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
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
		void * pK32 = ReCa<void*>(GetModuleHandleA("kernel32.dll"));
		DWORD dwOld = 0;

		BOOL bRet = VirtualProtectEx(hProc, hMod, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
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
		PEB * ppeb;
		ppeb = GetPEB(hProc);
		if (!ppeb)
			return INJ_ERR_CANT_GET_PEB;

		PEB	peb;
		if (!ReadProcessMemory(hProc, ppeb, &peb, sizeof(PEB), nullptr))
		{
			LastError = GetLastError();
			return INJ_ERR_CANT_ACCESS_PEB;
		}

		PEB_LDR_DATA ldrdata;
		if (!ReadProcessMemory(hProc, peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA), nullptr))
		{
			LastError = GetLastError();
			return INJ_ERR_CANT_ACCESS_PEB_LDR;
		}

		LDR_DATA_TABLE_ENTRY * pCurrentEntry	= reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldrdata.InLoadOrderModuleListHead.Flink);
		LDR_DATA_TABLE_ENTRY * pLastEntry		= reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldrdata.InLoadOrderModuleListHead.Blink);

		while (true)
		{
			LDR_DATA_TABLE_ENTRY CurrentEntry;
			ReadProcessMemory(hProc, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

			if (CurrentEntry.DllBase == hMod)
			{
				LIST_ENTRY flink;
				LIST_ENTRY blink;

				ReadProcessMemory(hProc, CurrentEntry.InLoadOrder.Flink, &flink, sizeof(LIST_ENTRY), nullptr);
				ReadProcessMemory(hProc, CurrentEntry.InLoadOrder.Blink, &blink, sizeof(LIST_ENTRY), nullptr);
				flink.Blink = CurrentEntry.InLoadOrder.Blink;
				blink.Flink = CurrentEntry.InLoadOrder.Flink;
				WriteProcessMemory(hProc, CurrentEntry.InLoadOrder.Flink, &flink, sizeof(LIST_ENTRY), nullptr);
				WriteProcessMemory(hProc, CurrentEntry.InLoadOrder.Blink, &blink, sizeof(LIST_ENTRY), nullptr);

				ReadProcessMemory(hProc, CurrentEntry.InMemoryOrder.Flink, &flink, sizeof(LIST_ENTRY), nullptr);
				ReadProcessMemory(hProc, CurrentEntry.InMemoryOrder.Blink, &blink, sizeof(LIST_ENTRY), nullptr);
				flink.Blink = CurrentEntry.InMemoryOrder.Blink;
				blink.Flink = CurrentEntry.InMemoryOrder.Flink;
				WriteProcessMemory(hProc, CurrentEntry.InMemoryOrder.Flink, &flink, sizeof(LIST_ENTRY), nullptr);
				WriteProcessMemory(hProc, CurrentEntry.InMemoryOrder.Blink, &blink, sizeof(LIST_ENTRY), nullptr);

				ReadProcessMemory(hProc, CurrentEntry.InInitOrder.Flink, &flink, sizeof(LIST_ENTRY), nullptr);
				ReadProcessMemory(hProc, CurrentEntry.InInitOrder.Blink, &blink, sizeof(LIST_ENTRY), nullptr);
				flink.Blink = CurrentEntry.InInitOrder.Blink;
				blink.Flink = CurrentEntry.InInitOrder.Flink;
				WriteProcessMemory(hProc, CurrentEntry.InInitOrder.Flink, &flink, sizeof(LIST_ENTRY), nullptr);
				WriteProcessMemory(hProc, CurrentEntry.InInitOrder.Blink, &blink, sizeof(LIST_ENTRY), nullptr);

				BYTE Buffer[MAX_PATH * 2]{ 0 };
				WriteProcessMemory(hProc, CurrentEntry.BaseDllName.szBuffer, Buffer, CurrentEntry.BaseDllName.MaxLength, nullptr);
				WriteProcessMemory(hProc, CurrentEntry.FullDllName.szBuffer, Buffer, CurrentEntry.FullDllName.MaxLength, nullptr);
				WriteProcessMemory(hProc, pCurrentEntry, Buffer, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

				return INJ_ERR_SUCCESS;
			}

			if (pCurrentEntry == pLastEntry)
			{
				LastError = INJ_ERR_ADV_CANT_FIND_MODULE;
				return INJ_ERR_CANT_FIND_MOD_PEB;
			}

			pCurrentEntry = ReCa<LDR_DATA_TABLE_ENTRY*>(CurrentEntry.InLoadOrder.Flink);
		}
	}
	
	return INJ_ERR_SUCCESS;
}

void __stdcall LoadLibraryShell(LOAD_LIBRARY_DATA * pData)
{
	if (!pData || !pData->pLoadLibraryA)
		return;

	pData->pLoadLibraryA(pData->szDll);
	pData->pLoadLibraryA = nullptr;
}

void __stdcall LdrLoadDllShell(LDR_LOAD_DLL_DATA * pData)
{
	if (!pData || !pData->pLdrLoadDll)
		return;

	pData->pModuleFileName.szBuffer = ReCa<wchar_t*>(pData->Data);
	pData->pLdrLoadDll(nullptr, 0, &pData->pModuleFileName, &pData->Out);
	pData->pLdrLoadDll = nullptr;
}

void __stdcall ImportTlsExecute(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->pLoadLibraryA)
		return;

	BYTE * pBase			= ReCa<BYTE*>(pData);
	auto * pOp				= &ReCa<IMAGE_NT_HEADERS*>(pBase + ReCa<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;
	auto _LoadLibrarA		= pData->pLoadLibraryA;
	auto _GetProcAddress	= pData->pGetProcAddress;
	DWORD _Flags			= pData->Flags;
	auto _DllMain			= ReCa<f_DLL_ENTRY_POINT>(pBase + pOp->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOp->ImageBase;
	if (LocationDelta)
	{
		if (!pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			WORD * pRelativeInfo = ReCa<WORD*>(pRelocData + 1);
			for (UINT i = 0; i < ((pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); ++i, ++pRelativeInfo)
			{
				if(RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR * pPatch = ReCa<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += ReCa<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(ReCa<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = ReCa<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibrarA(szMod);
			ULONG_PTR * pThunkRef	= ReCa<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR * pFuncRef	= ReCa<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (_Flags & INJ_CLEAN_DATA_DIR)
				_ZeroMemory(pBase + pImportDescr->Name, _strlenA(szMod));

			if (!pImportDescr->OriginalFirstThunk)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, ReCa<char*>(*pThunkRef & 0xFFFF));
					if (_Flags & INJ_CLEAN_DATA_DIR)
						_ZeroMemory(ReCa<BYTE*>(*pThunkRef & 0xFFFF), _strlenA(ReCa<char*>(*pThunkRef & 0xFFFF)));
				}
				else
				{
					auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
					if (_Flags & INJ_CLEAN_DATA_DIR)
						_ZeroMemory(ReCa<BYTE*>(pImport->Name), _strlenA(pImport->Name));
				}
			}
			++pImportDescr;
		}
	}

	if (pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	if (_Flags & INJ_CLEAN_DATA_DIR)
	{
		auto Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		if (Size)
		{
			_ZeroMemory(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, Size);
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
			Size = 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (Size)
		{
			_ZeroMemory(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, Size);
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
			Size = 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
		if (Size)
		{
			auto * pIDD = ReCa<IMAGE_DEBUG_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			if (pIDD->SizeOfData && pIDD->PointerToRawData)
			{
				_ZeroMemory(pBase + pIDD->PointerToRawData, pIDD->SizeOfData);
			}
			_ZeroMemory(ReCa<BYTE*>(pIDD), Size);
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
			Size = 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
		if (Size)
		{
			auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback) = nullptr;

			_ZeroMemory(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, Size);
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
			Size = 0;
		}
	}


	if(_Flags & INJ_ERASE_HEADER)
		for (UINT i = 0; i != 0x1000; i += sizeof(ULONG64))
			*ReCa<ULONG64*>(pBase + i) = 0;

	pData->pLoadLibraryA = nullptr;
}

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	HANDLE hProc = reinterpret_cast<HANDLE>(lParam);
	char szWindow[MAX_PATH]{ 0 };
	
	DWORD winPID = 0;
	DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);

	if (winPID == GetProcessId(hProc))
		if (IsWindowVisible(hWnd) && GetWindowTextA(hWnd, szWindow, MAX_PATH))
			if (GetClassNameA(hWnd, szWindow, MAX_PATH))
				if (strcmp(szWindow, "ConsoleWindowClass"))
				{
					g_hWnd = hWnd;
					g_TID = winTID;
				}

	return TRUE;
}

HANDLE StartRoutine(HANDLE hTargetProc, void * pRoutine, void * pArg, LAUNCH_METHOD Method, bool HideFromDebugger, bool Fastcall)
{
	if (Method == LM_NtCreateThreadEx)
	{
		auto _NtCTE = ReCa<f_NtCreateThreadEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
		if (!_NtCTE)
		{
			HANDLE hThread = CreateRemoteThreadEx(hTargetProc, nullptr, 0, ReCa<LPTHREAD_START_ROUTINE>(pRoutine), pArg, 0, nullptr, nullptr);
			if (!hThread)
				LastError = GetLastError();

			return hThread;
		}
		HANDLE hThread = nullptr;
		_NtCTE(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRoutine, pArg, ((HideFromDebugger == true) ? THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER : NULL), 0, 0, 0, nullptr);

		if(!hThread)
			LastError = GetLastError();

		return hThread;
	}
	else if(Method == LM_HijackThread)
	{
		DWORD dwProcId = GetProcessId(hTargetProc);
		if (!dwProcId)
		{
			LastError = INJ_ERR_ADV_INV_PROC;
			return nullptr;
		}

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!hSnap)
		{
			LastError = GetLastError();
			return nullptr;
		}

		THREADENTRY32 TE32 = { 0 };
		TE32.dwSize = sizeof(THREADENTRY32);

		BOOL Ret = Thread32First(hSnap, &TE32);
		while (Ret)
		{
			if (TE32.th32OwnerProcessID == dwProcId && TE32.th32ThreadID != GetCurrentThreadId())
				break;
			Ret = Thread32Next(hSnap, &TE32);
		}
		CloseHandle(hSnap);

		if (!Ret)
		{
			LastError = INJ_ERR_ADV_NO_THREADS;
			return nullptr;
		}

		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TE32.th32ThreadID);
		if (!hThread)
		{
			LastError = INJ_ERR_ADV_CANT_OPEN_THREAD;
			return nullptr;
		}

		if (SuspendThread(hThread) == (DWORD)-1)
		{
			LastError = INJ_ERR_ADV_SUSPEND_FAIL;
			CloseHandle(hThread);
			return nullptr;
		}

		CONTEXT OldContext;
		OldContext.ContextFlags = CONTEXT_CONTROL;
		if (!GetThreadContext(hThread, &OldContext))
		{
			LastError = INJ_ERR_ADV_GET_CONTEXT_FAIL;
			ResumeThread(hThread);
			CloseHandle(hThread);
			return nullptr;
		}

		void * pCodecave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pCodecave)
		{
			LastError = INJ_ERR_ADV_OUT_OF_MEMORY;
			ResumeThread(hThread);
			CloseHandle(hThread);
			return nullptr;
		}

		#ifdef _WIN64

		Fastcall = true;

		BYTE Shellcode[] =
		{
			0x48, 0x83, 0xEC, 0x08,												// + 0x00			-> sub rsp, 0x08

			0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,							// + 0x04 (+ 0x07)	-> mov [rsp], RipLowPart
			0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,						// + 0x0B (+ 0x0F)	-> mov [rsp + 04], RipHighPart		

			0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,	// + 0x13			-> push r(acd)x / r(8-11)
			0x9C,																// + 0x1E			-> pushfq

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// + 0x1F (+ 0x21)	-> mov rax, pFunc
			0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// + 0x29 (+ 0x2B)	-> mov rcx, pArg

			0x48, 0x83, 0xEC, 0x20,												// + 0x33			-> sub rsp, 0x20
			0xFF, 0xD0,															// + 0x37			-> call rax
			0x48, 0x83, 0xC4, 0x20,												// + 0x39			-> add rsp, 0x20

			0x9D,																// + 0x3D			-> popfq
			0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,	// + 0x3E			-> pop r(11-8) / r(dca)x

			0xC6, 0x05, 0xB0, 0xFF, 0xFF, 0xFF, 0x00,							// + 0x49			-> mov byte ptr[$ - 0x49], 0

			0xC3																// + 0x50			-> ret
		}; // SIZE = 0x51

		DWORD dwLoRIP = (DWORD)(OldContext.Rip & 0xFFFFFFFF);
		DWORD dwHiRIP = (DWORD)((OldContext.Rip >> 0x20) & 0xFFFFFFFF);

		*ReCa<DWORD*>(Shellcode + 0x07) = dwLoRIP;
		*ReCa<DWORD*>(Shellcode + 0x0F) = dwHiRIP;
		*ReCa<void**>(Shellcode + 0x21) = pRoutine;
		*ReCa<void**>(Shellcode + 0x2B) = pArg;

		OldContext.Rip = ReCa<DWORD64>(pCodecave);

		#else

		BYTE Shellcode[] =
		{
			0x83, 0xEC, 0x04,							// + 0x00				-> sub esp, 0x04
			0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov [esp], OldEip

			0x9C,										// + 0x0A				-> pushad
			0x60,										// + 0x0B				-> pushfd

			0xB9, 0x00, 0x00, 0x00, 0x00,				// + 0x0C (+ 0x0D)		-> mov ecx, pArg
			0xB8, 0x00, 0x00, 0x00, 0x00,				// + 0x11 (+ 0x12)		-> mov eax, pFunc

			0x51,										// + 0x16 (__stdcall)	-> push ecx	(default)
														// + 0x16 (__fastcall)	-> nop (0x90)
			0xFF, 0xD0,									// + 0x17				-> call eax

			0x61,										// + 0x19				-> popad
			0x9D,										// + 0x1A				-> popfd
			
			0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x1B (+ 0x1D)		-> mov byte ptr[pCodecave], 0
			
			0xC3										// + 0x22				-> ret
		}; // SIZE = 0x23

		if (!Fastcall)
			Shellcode[0x16] = 0x51;

		*ReCa<DWORD*>(Shellcode + 0x06) = OldContext.Eip;
		*ReCa<void**>(Shellcode + 0x0D) = pArg;
		*ReCa<void**>(Shellcode + 0x12) = pRoutine;
		*ReCa<void**>(Shellcode + 0x1D) = pCodecave;

		OldContext.Eip = ReCa<DWORD>(pCodecave);

		#endif

		if (!WriteProcessMemory(hTargetProc, pCodecave, Shellcode, sizeof(Shellcode), nullptr))
		{
			LastError = INJ_ERR_ADV_WPM_FAIL;
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
			ResumeThread(hThread);
			CloseHandle(hThread);
			return nullptr;
		}

		if (!SetThreadContext(hThread, &OldContext))
		{
			LastError = INJ_ERR_ADV_SET_CONTEXT_FAIL;
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
			ResumeThread(hThread);
			CloseHandle(hThread);
			return nullptr;
		}

		if (ResumeThread(hThread) == (DWORD)-1)
		{
			LastError = INJ_ERR_ADV_RESUME_FAIL;
			VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);
			CloseHandle(hThread);
			return nullptr;
		}

		BYTE CheckByte = 1;
		while (CheckByte)
		{
			ReadProcessMemory(hTargetProc, pCodecave, &CheckByte, 1, nullptr);
			Sleep(10);
		}

		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pCodecave, 0, MEM_RELEASE);

		return (HANDLE)1;
	}
	else if(Method == LM_SetWindowsHookEx)
	{
		EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(hTargetProc));
		if (!g_TID)
		{
			LastError = INJ_ERR_ADV_NO_WIN_THREAD;
			return nullptr;
		}

		BYTE * pShellcode = ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pShellcode)
		{
			LastError = GetLastError();
			return nullptr;
		}

		DWORD TestByteOffset = 0;

		#ifdef _WIN64

		BYTE Shellcode[] =
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// - 0x18			-> pArg 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				// - 0x10			-> pFunc

			0x9C,														// + 0x00			-> pushfq
			0x55,														// + 0x01			-> push rbp
			0x54,														// + 0x02			-> push rsp

			0x80, 0x3D, 0x02, 0x00, 0x00, 0x00, 0x00,					// + 0x03			-> cmp byte ptr[pCodecave + 0x0C (+ 0x10)], 0x00
			0x74, 0x1F,													// + 0x0A			-> je pCodecave + 0x2B (+ 0x10)

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // + 0x0C (+ 0x0E)	-> mov rax, pCodecave
			0x48, 0x8B, 0x08, 											// + 0x16			-> mov rcx, [rax]
			0x48, 0x83, 0xEC, 0x20,										// + 0x19			-> sub rsp, 0x20
			0xFF, 0x50, 0x08,											// + 0x1D			-> call [rax + 0x08]
			0x48, 0x83, 0xC4, 0x20, 									// + 0x20			-> add rsp, 0x20
			0xC6, 0x05, 0xE1, 0xFF, 0xFF, 0xFF, 0x00,					// + 0x24			-> mov byte ptr[pCodecave + 0x0C (+ 0x10)], 0x00

			0x5C,														// + 0x2B			-> pop rsp
			0x5D,														// + 0x2C			-> pop rbp
			0x9D,														// + 0x2D			-> popfq

			0xC3														// + 0x2E			-> ret
		}; // SIZE = 0x2F (+ 0x10)

		*ReCa<void**>(Shellcode + 0x00) = pArg;
		*ReCa<void**>(Shellcode + 0x08) = pRoutine;

		*ReCa<void**>(Shellcode + 0x0E + 0x10) = pShellcode;

		TestByteOffset = 0x0C + 0x10;

		#else

		BYTE Shellcode[] =
		{
			0x00, 0x00, 0x00, 0x00,											// - 0x08			-> pArg 
			0x00, 0x00, 0x00, 0x00,											// - 0x04			-> pFunc

			0x55,															// + 0x00			-> push ebp
			0x8B, 0xEC,														// + 0x01			-> mov ebp, esp

			0x9C,															// + 0x03			-> pushfd
			0x53,															// + 0x04			-> push ebx

			0xBB, 0x00, 0x00, 0x00, 0x00,									// + 0x05 (+ 0x06)	-> mov ebx, pArg (ebx = pCodecave)
			0x80, 0x7B, 0x18, 0x00,											// + 0x0A			-> cmp byte ptr[ebx + 0x18], 0x00 (ebx = pCodecave)
			0x74, 0x09,														// + 0x0E			-> je pCodecave + 0x18

			0xFF, 0x33,														// + 0x10			-> push [ebx]
			0xFF, 0x53, 0x04,												// + 0x12			-> call [ebx + 0x04]
			0xC6, 0x43, 0x18, 0x00,											// + 0x15			-> mov byte ptr[ebx + 0x18], 0x00 (ebx = pCodecave)

			0x5B,															// + 0x27			-> pop ebx
			0x9D,															// + 0x28			-> popfd

			0x5D,															// + 0x29			-> pop ebp
			0xC2, 0x0C, 0x00												// + 0x2A			-> ret 0x0C
		}; // SIZE = 0x2D (+ 0x08)

		*ReCa<void**>(Shellcode + 0x00)			= pArg;
		*ReCa<void**>(Shellcode + 0x04)			= pRoutine;

		*ReCa<void**>(Shellcode + 0x09 + 0x05)	= pShellcode;

		TestByteOffset = 0x0F + 0x09;

		#endif
		
		if (!WriteProcessMemory(hTargetProc, pShellcode, Shellcode, sizeof(Shellcode), nullptr))
		{
			LastError = GetLastError();
			VirtualFreeEx(hTargetProc, pShellcode, 0, MEM_RELEASE);
			return nullptr;
		}

		HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, ReCa<HOOKPROC>(pShellcode + sizeof(void*) * 2), GetModuleHandleA("kernel32.dll"), g_TID);

		if (!hHook)
		{
			LastError = GetLastError();
			VirtualFreeEx(hTargetProc, pShellcode, 0, MEM_RELEASE);
			return nullptr;
		}

		Sleep(25);

		SetForegroundWindow(g_hWnd);
		SendMessageA(g_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(25);
		SendMessageA(g_hWnd, WM_KEYUP, VK_SPACE, 0);

		BYTE Test = 1;
		while (Test)
		{
			ReadProcessMemory(hTargetProc, pShellcode + TestByteOffset, &Test, sizeof(Test), nullptr);
			Sleep(10);
		}
		
		UnhookWindowsHookEx(hHook);
		
		VirtualFreeEx(hTargetProc, pShellcode, 0, MEM_RELEASE);

		return (HANDLE)1;
	}
	else if (Method == LM_UserAPC)
	{
		DWORD PID = GetProcessId(hTargetProc);
		DWORD QueueRet = 0;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
		THREADENTRY32 TE32{ 0 };
		TE32.dwSize = sizeof(THREADENTRY32);

		BOOL Ret = Thread32First(hSnap, &TE32);
		while (Ret)
		{
			if (TE32.th32OwnerProcessID == PID)
			{
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, TE32.th32ThreadID);
				if (hThread)
				{
					QueueRet = QueueUserAPC(ReCa<PAPCFUNC>(pRoutine), hThread, ReCa<ULONG_PTR>(pArg));
					CloseHandle(hThread);
				}
			}
			Ret = Thread32Next(hSnap, &TE32);
		}

		while (QueueRet)
		{
			DWORD Test = 0;
			ReadProcessMemory(hTargetProc, pArg, &Test, sizeof(Test), nullptr);
			if (Test)
				return (HANDLE)1;

			Sleep(10);
		}

		LastError = INJ_ERR_ADV_NO_APC_THREAD;

		return nullptr;
	}

	return nullptr;
}

PEB * GetPEB(HANDLE hProc)
{
	auto _NtQIP = reinterpret_cast<f_NtQueryInformationProcess>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
	if (!_NtQIP)
	{
		LastError = INJ_ERR_ADV_QIP_MISSING;
		return nullptr;
	}

	PROCESS_BASIC_INFORMATION PBI{ 0 };
	ULONG SizeOut = 0;
	if (_NtQIP(hProc, PROCESSINFOCLASS::ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &SizeOut) < 0)
	{
		LastError = INJ_ERR_ADV_QIP_FAIL;
		return nullptr;
	}

	return PBI.pPEB;
}