#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

DWORD LastError = INJ_ERR_SUCCESS;
DWORD g_TID		= 0;
HWND g_hWnd		= NULL;

DWORD LoadLibraryStub	(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut);
DWORD ManualMap			(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut);
DWORD LdrLoadDllStub	(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut);

DWORD Cloaking			(HANDLE hProc, DWORD Flags, HINSTANCE hMod);

HINSTANCE __stdcall LoadLibraryShell	(LOAD_LIBRARY_DATA		* pData);
HINSTANCE __stdcall LdrLoadDllShell		(LDR_LOAD_DLL_DATA		* pData);
HINSTANCE __stdcall ManualMapShell		(MANUAL_MAPPING_DATA	* pData);

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

	if (Flags & INJ_LOAD_DLL_COPY)
	{
		const char * pFileName = szDllFile;
		pFileName += strlen(pFileName) - 1;
		while (*(pFileName - 1) != '\\')
			--pFileName;
		
		char new_path[MAX_PATH]{ 0 };
		GetTempPathA(MAX_PATH, new_path);
		strcat_s(new_path, pFileName);

		CopyFileA(szDllFile, new_path, FALSE);

		szDllFile = new_path;
	}

	if (Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		char new_name[15]{ 0 };
		for (UINT i = 0; i != 10; ++i)
		{
			srand(GetTickCount() + rand() + Flags + LOWORD(hProc));
			auto val = rand() % 3;
			if (val == 0)
			{
				val = rand() % 10;
				new_name[i] = char('0' + val);
			}
			else if (val == 1)
			{
				val = rand() % 10;
				new_name[i] = char('A' + val);
			}
			else
			{
				val = rand() % 10;
				new_name[i] = char('a' + val);
			}
		}
		new_name[10] = '.';
		new_name[11] = 'd';
		new_name[12] = 'l';
		new_name[13] = 'l';
		new_name[14] = '\0';

		char OldFilePath[MAX_PATH]{ 0 };
		strcpy_s(OldFilePath, szDllFile);

		char * pFileName = const_cast<char*>(szDllFile);
		pFileName += strlen(pFileName);
		while (*(pFileName - 1) != '\\')
			--pFileName;

		memcpy(pFileName, new_name, 15);

		rename(OldFilePath, szDllFile);
	}

	DWORD Ret = 0;

	HINSTANCE hOut = NULL;

	switch (im)
	{
		case IM_LoadLibrary:
			Ret = LoadLibraryStub(szDllFile, hProc, Method, Flags, hOut);
			break;

		case IM_LdrLoadDll:
			Ret = LdrLoadDllStub(szDllFile, hProc, Method, Flags, hOut);
			break;

		case IM_ManualMap:
			Ret = ManualMap(szDllFile, hProc, Method, Flags, hOut);
	}

	if (Ret == INJ_ERR_SUCCESS && hOut && im != IM_ManualMap)
		Ret = Cloaking(hProc, Flags, hOut);

	if (ErrorCode)
		*ErrorCode = LastError;

	return Ret;
}

DWORD LoadLibraryStub(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut)
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
		return INJ_ERR_REMOTEFUNC_MISSING;
	}
	
	data.pLoadLibraryA = ReCa<f_LoadLibraryA*>(pLoadLibraryA);

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

	auto * pShell = ReCa<BYTE*>(ALIGN_UP(ReCa<UINT_PTR>(pArg + sizeof(LOAD_LIBRARY_DATA)), 0x10));
	if (!WriteProcessMemory(hProc, pShell, LoadLibraryShell, 0x100, nullptr))
	{
		LastError = GetLastError();

		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}
	
	DWORD dwRet = StartRoutine(hProc, pShell, pArg, Method, (Flags & INJ_HIDE_THREAD_FROM_DEBUGGER) != 0, CC_STDCALL, LastError, hOut);
	
	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
	
	return dwRet;
}

DWORD LdrLoadDllStub(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut)
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

	DWORD dwRet = StartRoutine(hProc, pArg + sizeof(LDR_LOAD_DLL_DATA), pArg, Method, (Flags & INJ_HIDE_THREAD_FROM_DEBUGGER) != 0, CC_STDCALL, LastError, hOut);
	
	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

	return dwRet;
}

DWORD ManualMap(const char * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut)
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
		return INJ_ERR_FILE_DOESNT_EXIST;
	
	BYTE *					pSrcData		= nullptr;
	IMAGE_NT_HEADERS *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *		pOldFileHeader	= nullptr;
	BYTE *					pLocalBase		= nullptr;
	BYTE *					pAllocBase		= nullptr;
	BYTE *					pTargetBase		= nullptr;
	BYTE *					pArg			= nullptr;

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	auto FileSize = File.tellg();

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];

	if (!pSrcData)
	{
		File.close();
		return INJ_ERR_OUT_OF_MEMORY;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pSrcData), FileSize);
	File.close();

	pOldNtHeader	= ReCa<IMAGE_NT_HEADERS*>(pSrcData + ReCa<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader	= &pOldNtHeader->OptionalHeader;
	pOldFileHeader	= &pOldNtHeader->FileHeader;

	DWORD ShiftOffset = 0;
	if (Flags & INJ_SHIFT_MODULE)
	{
		srand(GetTickCount() + pOldOptHeader->SizeOfImage);
		ShiftOffset = rand() % 0x1000 + 0x100;
	}

	auto AllocSize = pOldOptHeader->SizeOfImage + ShiftOffset + sizeof(MANUAL_MAPPING_DATA) + 0x100;
	pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hProc, ReCa<void*>(pOldOptHeader->ImageBase), AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pAllocBase)
		pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pAllocBase)
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

	pArg = ReCa<BYTE*>(ALIGN_UP(ReCa<UINT_PTR>(pAllocBase + ShiftOffset), 0x10));
	pTargetBase = ReCa<BYTE*>(ALIGN_IMAGE_BASE(ReCa<UINT_PTR>(pArg + sizeof(MANUAL_MAPPING_DATA))));
	
	memset(pLocalBase, 0, pOldOptHeader->SizeOfImage);
	memcpy(pLocalBase, pSrcData, 0x1000);
	
	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i < pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		if (pSectionHeader->SizeOfRawData)
			memcpy(pLocalBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);

	BYTE * LocationDelta = pTargetBase - pOldOptHeader->ImageBase;
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
				if(RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR * pPatch = ReCa<UINT_PTR*>(pLocalBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += ReCa<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(ReCa<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	auto LoadFunctionPointer = [=](char * szLib, char * szFunc, void * &pOut)
	{
		if (!GetImportA(hProc, szLib, szFunc, pOut))
		{
			delete[] pSrcData;
			VirtualFree(pLocalBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pTargetBase - ShiftOffset, 0, MEM_RELEASE);
			return false;
		}

		return true;
	};

	void * pLoadLibraryA = nullptr;
	if (!LoadFunctionPointer("kernel32.dll", "LoadLibraryA", pLoadLibraryA))
		return INJ_ERR_REMOTEFUNC_MISSING;
	
	void * pGetProcAddress = nullptr;
	if (!LoadFunctionPointer("kernel32.dll", "GetProcAddress", pGetProcAddress))
		return INJ_ERR_REMOTEFUNC_MISSING;

	void * pVirtualAlloc = nullptr;
	if (!LoadFunctionPointer("kernel32.dll", "VirtualAlloc", pVirtualAlloc))
		return INJ_ERR_REMOTEFUNC_MISSING;
	
	void * pVirtualFree = nullptr;
	if (!LoadFunctionPointer("kernel32.dll", "VirtualFree", pVirtualFree))
		return INJ_ERR_REMOTEFUNC_MISSING;
	
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA		= ReCa<f_LoadLibraryA*>		(pLoadLibraryA);
	data.pGetProcAddress	= ReCa<f_GetProcAddress>	(pGetProcAddress);
	data.pVirtualAlloc		= ReCa<f_VirtualAlloc*>		(pVirtualAlloc);
	data.pVirtualFree		= ReCa<f_VirtualFree*>		(pVirtualFree);
	data.pModuleBase		= pTargetBase;
	data.Flags				= Flags;
	
	BOOL bRet = WriteProcessMemory(hProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr);
	if (!bRet || !WriteProcessMemory(hProc, pTargetBase, pLocalBase, pOldOptHeader->SizeOfImage, nullptr))
	{
		LastError = GetLastError();
		delete[] pSrcData;
		VirtualFree(pLocalBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pAllocBase, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	delete[] pSrcData;
	VirtualFree(pLocalBase, 0, MEM_RELEASE);

	ULONG_PTR FuncSize = 0x800;
	void * pFunc = VirtualAllocEx(hProc, nullptr, FuncSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pFunc)
	{
		LastError = GetLastError();
		return INJ_ERR_CANT_ALLOC_MEM;
	}

	if (!WriteProcessMemory(hProc, pFunc, ManualMapShell, FuncSize, nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pFunc, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	DWORD dwRet = StartRoutine(hProc, pFunc, pArg, Method, (Flags & INJ_HIDE_THREAD_FROM_DEBUGGER) != 0, CC_STDCALL, LastError, hOut);

	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pFunc, 0, MEM_RELEASE);

	if (Flags & INJ_FAKE_HEADER)
	{
		void * pK32 = ReCa<void*>(GetModuleHandleA("kernel32.dll"));
		WriteProcessMemory(hProc, pTargetBase, pK32, 0x1000, nullptr);
	}

	return dwRet;
}

DWORD Cloaking(HANDLE hProc, DWORD Flags, HINSTANCE hMod)
{
	if (!Flags)
		return INJ_ERR_SUCCESS;

	if (Flags > INJ_MAX_FLAGS)
		return INJ_ERR_INVALID_FLAGS;

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
		ProcessInfo ProcInfo;
		ProcInfo.SetProcess(hProc);

		PEB * ppeb = ProcInfo.GetPEB();

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

		LIST_ENTRY * pCurrentEntry	= ldrdata.InLoadOrderModuleListHead.Flink;
		LIST_ENTRY * pLastEntry		= ldrdata.InLoadOrderModuleListHead.Blink;

		while (true)
		{
			LDR_DATA_TABLE_ENTRY CurrentEntry;
			ReadProcessMemory(hProc, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

			if (CurrentEntry.DllBase == hMod)
			{
				auto Unlink = [=](LIST_ENTRY entry)
				{
					LIST_ENTRY list;
					ReadProcessMemory(hProc, entry.Flink, &list, sizeof(LIST_ENTRY), nullptr);
					list.Blink = entry.Blink;
					WriteProcessMemory(hProc, entry.Flink, &list, sizeof(LIST_ENTRY), nullptr);

					ReadProcessMemory(hProc, entry.Blink, &list, sizeof(LIST_ENTRY), nullptr);
					list.Flink = entry.Flink;
					WriteProcessMemory(hProc, entry.Blink, &list, sizeof(LIST_ENTRY), nullptr);
				};

				Unlink(CurrentEntry.InLoadOrder);
				Unlink(CurrentEntry.InMemoryOrder);
				Unlink(CurrentEntry.InInitOrder);

				BYTE Buffer[MAX_PATH * 2]{ 0 };
				WriteProcessMemory(hProc, CurrentEntry.BaseDllName.szBuffer, Buffer, CurrentEntry.BaseDllName.MaxLength, nullptr);
				WriteProcessMemory(hProc, CurrentEntry.FullDllName.szBuffer, Buffer, CurrentEntry.FullDllName.MaxLength, nullptr);
				WriteProcessMemory(hProc, pCurrentEntry, Buffer, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

				return INJ_ERR_SUCCESS;
			}

			if (pCurrentEntry == pLastEntry)
			{
				return INJ_ERR_CANT_FIND_MOD_PEB;
			}

			pCurrentEntry = CurrentEntry.InLoadOrder.Flink;
		}
	}
	
	return INJ_ERR_SUCCESS;
}

HINSTANCE __stdcall LoadLibraryShell(LOAD_LIBRARY_DATA * pData)
{
	if (!pData || !pData->pLoadLibraryA)
		return NULL;

	HINSTANCE hDll = pData->pLoadLibraryA(pData->szDll);
	pData->pLoadLibraryA = nullptr;
	pData->hRet = hDll;

	return pData->hRet;
}

HINSTANCE __stdcall LdrLoadDllShell(LDR_LOAD_DLL_DATA * pData)
{
	if (!pData || !pData->pLdrLoadDll)
		return NULL;

	pData->pModuleFileName.szBuffer = ReCa<wchar_t*>(pData->Data);
	pData->pLdrLoadDll(nullptr, 0, &pData->pModuleFileName, &pData->hRet);
	pData->pLdrLoadDll = nullptr;

	return ReCa<HINSTANCE>(pData->hRet);
}

HINSTANCE __stdcall ManualMapShell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->pLoadLibraryA)
		return NULL;

	BYTE * pBase			= pData->pModuleBase;
	auto * pOp				= &ReCa<IMAGE_NT_HEADERS*>(pBase + ReCa<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;
	auto _GetProcAddress	= pData->pGetProcAddress;
	DWORD _Flags			= pData->Flags;
	auto _DllMain			= ReCa<f_DLL_ENTRY_POINT>(pBase + pOp->AddressOfEntryPoint);

	if (pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = ReCa<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = pData->pLoadLibraryA(szMod);
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
						*ReCa<WORD*>(pThunkRef) = 0;
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
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (Size)
		{
			_ZeroMemory(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, Size);
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
		if (Size)
		{
			auto * pIDD = ReCa<IMAGE_DEBUG_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
			if (pIDD->SizeOfData && pIDD->PointerToRawData)
			{
				_ZeroMemory(pBase + pIDD->PointerToRawData, pIDD->SizeOfData);
			}
			_ZeroMemory(ReCa<BYTE*>(pIDD), Size);
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		}
	}
	
	if(_Flags & INJ_ERASE_HEADER)
		for (UINT i = 0; i != 0x1000; i += sizeof(ULONG64))
			*ReCa<ULONG64*>(pBase + i) = 0;

	pData->pLoadLibraryA	= nullptr;
	pData->hRet				= ReCa<HINSTANCE>(pBase);

	return pData->hRet;
}