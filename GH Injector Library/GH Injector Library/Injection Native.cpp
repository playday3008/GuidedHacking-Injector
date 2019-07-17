#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

DWORD InitErrorStruct(const wchar_t * szDllPath, INJECTIONDATAW * pData, bool bNative, DWORD RetVal);

DWORD InjectDLL(const wchar_t * szDllFile, HANDLE hProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, DWORD & LastError, HINSTANCE & hOut);

DWORD _LoadLibrary	(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError);
DWORD _LdrLoadDll	(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError);
DWORD _ManualMap	(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError);

DWORD Cloaking			(HANDLE hProc, DWORD Flags, HINSTANCE hMod, DWORD & LastError);

HINSTANCE __stdcall LoadLibraryShell	(LOAD_LIBRARY_DATA		* pData);
DWORD LoadLibraryShell_End();
HINSTANCE __stdcall LdrLoadDllShell		(LDR_LOAD_DLL_DATA		* pData);
DWORD LdrLoadDllShell_End();
HINSTANCE __stdcall ManualMapShell		(MANUAL_MAPPING_DATA	* pData);
DWORD ManualMapShell_End();

DWORD InitErrorStruct(const wchar_t * szDllPath, INJECTIONDATAW * pData, bool bNative, DWORD RetVal)
{
	if (!RetVal)
		return INJ_ERR_SUCCESS;

	ERROR_INFO info{ 0 };
	info.szDllFileName		= szDllPath;
	info.TargetProcessId	= pData->ProcessID;
	info.InjectionMode		= pData->Mode;
	info.LaunchMethod		= pData->Method;
	info.Flags				= pData->Flags;
	info.ErrorCode			= RetVal;
	info.LastWin32Error		= pData->LastErrorCode;
	info.HandleValue		= pData->hHandleValue;
	info.bNative			= bNative;

	ErrorLog(&info);

	return RetVal;
}

DWORD __stdcall InjectA(INJECTIONDATAA * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)
	
	if (!pData->szDllPath)
		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW*>(pData), false, INJ_ERR_INVALID_FILEPATH);
	
	INJECTIONDATAW data{ 0 };
	size_t len_out = 0;
	size_t max_len = sizeof(data.szDllPath) / sizeof(wchar_t);
	StringCchLengthA(pData->szDllPath, max_len, &len_out);
	mbstowcs_s(&len_out, const_cast<wchar_t*>(data.szDllPath), max_len, pData->szDllPath, max_len);

	data.ProcessID		= pData->ProcessID;
	data.Mode			= pData->Mode;
	data.Method			= pData->Method;
	data.Flags			= pData->Flags;
	data.hHandleValue	= pData->hHandleValue;

	return InjectW(&data);	
}

DWORD __stdcall InjectW(INJECTIONDATAW * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	DWORD ErrOut = 0;
	
	if (!pData->szDllPath)
		return InitErrorStruct(nullptr, pData, false, INJ_ERR_INVALID_FILEPATH);

	const wchar_t * szDllPath = pData->szDllPath;

	if (!pData->ProcessID)
		return InitErrorStruct(szDllPath, pData, false, INJ_ERR_INVALID_PID);

	if (!FileExists(szDllPath))
	{
		pData->LastErrorCode = GetLastError();
		return InitErrorStruct(szDllPath, pData, false, INJ_ERR_FILE_DOESNT_EXIST);
	}

	HANDLE hProc = nullptr;
	if (pData->Flags & INJ_HIJACK_HANDLE)
	{
		if (pData->hHandleValue) 
		{
			hProc = (HANDLE)(UINT_PTR)pData->hHandleValue;
		}
		else
		{
			auto handles = FindProcessHandles(pData->ProcessID, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION);
			if (handles.empty())
			{
				return InitErrorStruct(szDllPath, pData, false, INJ_ERR_NO_HANDLES);
			}
			
			HANDLE hTargetProc = nullptr;
			handle_data handle{ 0 };
			for (auto i : handles)
			{
				hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, i.OwnerPID);
				if (hTargetProc)
				{
					if (IsNativeProcess(hTargetProc) && IsElevatedProcess(hTargetProc))
					{
						handle = i;
						break;
					}
					CloseHandle(hTargetProc);
					hTargetProc = nullptr;
				}
			}

			if (!handle.OwnerPID)
			{
				CloseHandle(hTargetProc);
				return InitErrorStruct(szDllPath, pData, false, INJ_ERR_HIJACK_NO_NATIVE_HANDLE);
			}
			
			if (!hTargetProc)
			{
				pData->LastErrorCode = GetLastError();
				return InitErrorStruct(szDllPath, pData, false, INJ_ERR_CANT_OPEN_OWNER_PROC);
			}
			
			HINSTANCE hInjectionModuleEx = GetModuleHandleExA(hTargetProc, GH_INJ_MOD_NAMEA);

			if (!hInjectionModuleEx)
			{
				INJECTIONDATAW hijack_data{ 0 };
				hijack_data.ProcessID = handle.OwnerPID;
				hijack_data.Mode = IM_LoadLibrary;
				hijack_data.Method = LM_NtCreateThreadEx;
				GetOwnModulePath(const_cast<wchar_t*>(hijack_data.szDllPath), sizeof(hijack_data.szDllPath) / sizeof(szDllPath[0]));
				StringCbCatW(const_cast<wchar_t*>(hijack_data.szDllPath), sizeof(hijack_data.szDllPath), GH_INJ_MOD_NAMEW);

				DWORD inj_ret = InjectW(&hijack_data);

				if (inj_ret || !hijack_data.hDllOut)
				{
					CloseHandle(hTargetProc);
					return InitErrorStruct(szDllPath, &hijack_data, true, INJ_ERR_HIJACK_INJ_FAILED);
				}
			}

			hInjectionModuleEx = GetModuleHandleExA(hTargetProc, GH_INJ_MOD_NAMEA);
			if (!hInjectionModuleEx)
			{
				CloseHandle(hTargetProc);
				return InitErrorStruct(szDllPath, pData, true, INJ_ERR_HIJACK_INJECTW_MISSING);
			}

			void * pRemoteInjectW = nullptr;
			bool bLoaded = GetImportA(hInjectionModuleEx, GH_INJ_MOD_NAMEA, "InjectW", pRemoteInjectW);
			if (!bLoaded)
			{
				EjectDll(hTargetProc, hInjectionModuleEx);
				CloseHandle(hTargetProc);
				return InitErrorStruct(szDllPath, pData, true, INJ_ERR_HIJACK_INJECTW_MISSING);
			}
			
			pData->hHandleValue = (DWORD)handle.hValue;

			void * pArg = VirtualAllocEx(hTargetProc, nullptr, sizeof(INJECTIONDATAW), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!pArg)
			{
				pData->LastErrorCode = GetLastError();
				EjectDll(hTargetProc, hInjectionModuleEx);
				CloseHandle(hTargetProc);

				return InitErrorStruct(szDllPath, pData, true, INJ_ERR_HIJACK_CANT_ALLOC);
			}

			if (!WriteProcessMemory(hTargetProc, pArg, pData, sizeof(INJECTIONDATAW), nullptr))
			{				
				pData->LastErrorCode = GetLastError();

				VirtualFreeEx(hTargetProc, pArg, 0, MEM_RELEASE);
				EjectDll(hTargetProc, hInjectionModuleEx);
				CloseHandle(hTargetProc);

				return InitErrorStruct(szDllPath, pData, true, INJ_ERR_HIJACK_CANT_WPM);
			}

			DWORD win32err = 0;
			HINSTANCE hOut = NULL;
			DWORD remote_ret = StartRoutine(hTargetProc, pRemoteInjectW, pArg, LM_NtCreateThreadEx, true, CC_STDCALL, win32err, hOut);
			
			VirtualFreeEx(hTargetProc, pArg, 0, MEM_RELEASE);
			EjectDll(hTargetProc, hInjectionModuleEx);
			CloseHandle(hTargetProc);
			
			if (remote_ret == SR_ERR_SUCCESS && win32err)
			{
				DWORD remote_error = (DWORD)((UINT_PTR)hOut & 0xFFFFFFFF);
				pData->LastErrorCode = remote_error;
				return InitErrorStruct(szDllPath, pData, true, win32err);
			}
		
			pData->LastErrorCode = win32err;
			return InitErrorStruct(szDllPath, pData, true, remote_ret);
		}
	}
	else
	{
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pData->ProcessID);
		if (!hProc)
		{
			pData->LastErrorCode = GetLastError();
			return InitErrorStruct(szDllPath, pData, false, INJ_ERR_CANT_OPEN_PROCESS);
		}
	}

	DWORD handle_info = 0;
	if (!hProc || !GetHandleInformation(hProc, &handle_info))
	{
		pData->LastErrorCode = GetLastError();
		return InitErrorStruct(szDllPath, pData, false, INJ_ERR_INVALID_PROC_HANDLE);
	}

	bool native_target = true;
#ifdef _WIN64
	native_target = IsNativeProcess(hProc);
	if (native_target)
	{
		ErrOut = ValidateFile(szDllPath, IMAGE_FILE_MACHINE_AMD64);
	}
	else
	{
		ErrOut = ValidateFile(szDllPath, IMAGE_FILE_MACHINE_I386);
	}
#else
	ErrOut = ValidateFile(szDllPath, IMAGE_FILE_MACHINE_I386);
#endif

	if (ErrOut)
	{
		pData->LastErrorCode = ErrOut;
			return InitErrorStruct(szDllPath, pData, native_target, INJ_ERR_PLATFORM_MISMATCH);
	}
	
	HINSTANCE hOut	= NULL;
	DWORD RetVal	= INJ_ERR_SUCCESS;
#ifdef _WIN64
	if (!native_target)
	{
		RetVal = InjectDLL_WOW64(szDllPath, hProc, pData->Mode, pData->Method, pData->Flags, ErrOut, hOut);
	}
	else
	{		
		RetVal = InjectDLL(szDllPath, hProc, pData->Mode, pData->Method, pData->Flags, ErrOut, hOut);
	}	
#else
	RetVal = InjectDLL(szDllPath, hProc, pData->Mode, pData->Method, pData->Flags, ErrOut, hOut);
#endif

	if (!(pData->Flags & INJ_HIJACK_HANDLE))
		CloseHandle(hProc);
	
	pData->LastErrorCode	= ErrOut;
	pData->hDllOut			= hOut;

	return InitErrorStruct(szDllPath, pData, native_target, RetVal);
}

DWORD InjectDLL(const wchar_t * szDllFile, HANDLE hProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, DWORD & LastError, HINSTANCE & hOut)
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
			Ret = _LoadLibrary(szDllFile, hProc, Method, Flags, hOut, LastError);
			break;

		case IM_LdrLoadDll:
			Ret = _LdrLoadDll(szDllFile, hProc, Method, Flags, hOut, LastError);
			break;

		case IM_ManualMap:
			Ret = _ManualMap(szDllFile, hProc, Method, Flags, hOut, LastError);
	}

	if (Ret == INJ_ERR_SUCCESS && hOut && im != IM_ManualMap)
		Ret = Cloaking(hProc, Flags, hOut, LastError);
	
	return Ret;
}

DWORD _LoadLibrary(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	LOAD_LIBRARY_DATA data{ 0 };
	StringCchCopyW(data.szDll, sizeof(data.szDll) / sizeof(wchar_t), szDllFile);

	void * pLoadLibraryExW = nullptr;
	char sz_LoadLibName[] = "LoadLibraryExW";

	if (!GetImportA(hProc, "kernel32.dll", sz_LoadLibName, pLoadLibraryExW))
	{
		LastError = GetLastError();
		return INJ_ERR_REMOTEFUNC_MISSING;
	}
	
	data.pLoadLibraryExW = ReCa<f_LoadLibraryExW*>(pLoadLibraryExW);

	size_t ShellSize = (UINT_PTR)LoadLibraryShell_End - (UINT_PTR)LoadLibraryShell;

	BYTE * pArg = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(LOAD_LIBRARY_DATA) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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
	if (!WriteProcessMemory(hProc, pShell, LoadLibraryShell, ShellSize, nullptr))
	{
		LastError = GetLastError();

		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}
	
	DWORD dwRet = StartRoutine(hProc, pShell, pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, CC_STDCALL, LastError, hOut);
	
	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
	
	return dwRet;
}

DWORD _LdrLoadDll(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	size_t size_out = 0;

	LDR_LOAD_DLL_DATA data{ 0 };
	data.pModuleFileName.MaxLength = sizeof(data.Data);
	StringCbLengthW(szDllFile, data.pModuleFileName.MaxLength, &size_out);
	StringCbCopyW(ReCa<wchar_t*>(data.Data), data.pModuleFileName.MaxLength, szDllFile);
	data.pModuleFileName.Length = (WORD)size_out;

	void * pLdrLoadDll = nullptr;
	if (!GetImportA(hProc, "ntdll.dll", "LdrLoadDll", pLdrLoadDll))
	{
		LastError = GetLastError();
		return INJ_ERR_LDRLOADDLL_MISSING;
	}
	data.pLdrLoadDll = ReCa<f_LdrLoadDll>(pLdrLoadDll);

	

	size_t ShellSize = (UINT_PTR)LdrLoadDllShell_End - (UINT_PTR)LdrLoadDllShell;
	BYTE * pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(LDR_LOAD_DLL_DATA) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg		= pAllocBase;
	BYTE * pFunc	= ReCa<BYTE*>(ALIGN_UP(ReCa<UINT_PTR>(pArg) + sizeof(LDR_LOAD_DLL_DATA), 0x10));

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

	if (!WriteProcessMemory(hProc, pFunc, LdrLoadDllShell, ShellSize, nullptr))
	{
		LastError = GetLastError();
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		return INJ_ERR_WPM_FAIL;
	}

	DWORD dwRet = StartRoutine(hProc, pFunc, pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, CC_STDCALL, LastError, hOut);
	ReadProcessMemory(hProc, pArg, &data, sizeof(data), nullptr);

	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);

	return dwRet;
}

DWORD _ManualMap(const wchar_t * szDllFile, HANDLE hProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	BYTE *					pSrcData		= nullptr;
	IMAGE_NT_HEADERS *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *		pOldFileHeader	= nullptr;
	BYTE *					pLocalBase		= nullptr;
	BYTE *					pAllocBase		= nullptr;
	BYTE *					pTargetBase		= nullptr;
	BYTE *					pArg			= nullptr;
	BYTE *					pFunc			= nullptr;

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

	pOldNtHeader	= ReCa<IMAGE_NT_HEADERS*>(pSrcData + ReCa<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader	= &pOldNtHeader->OptionalHeader;
	pOldFileHeader	= &pOldNtHeader->FileHeader;

	DWORD ShiftOffset = 0;
	if (Flags & INJ_SHIFT_MODULE)
	{
		srand(GetTickCount() + pOldOptHeader->SizeOfImage);
		ShiftOffset = rand() % 0x1000 + 0x100;
	}

	size_t ShellSize	= (UINT_PTR)ManualMapShell_End - (UINT_PTR)ManualMapShell;
	auto AllocSize		= ShiftOffset + pOldOptHeader->SizeOfImage + sizeof(MANUAL_MAPPING_DATA) + ShellSize + 0x30;

	pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hProc, ReCa<void*>(pOldOptHeader->ImageBase), AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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

	pTargetBase = ReCa<BYTE*>(ALIGN_IMAGE_BASE	(ReCa<UINT_PTR>(pAllocBase)		+ ShiftOffset));
	pArg		= ReCa<BYTE*>(ALIGN_UP			(ReCa<UINT_PTR>(pTargetBase)	+ pOldOptHeader->SizeOfImage, 0x10));
	pFunc		= ReCa<BYTE*>(ALIGN_UP			(ReCa<UINT_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA), 0x10));

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
			return INJ_ERR_IMAGE_CANT_RELOC;

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

	auto LoadFunctionPointer = [=](const char * szLib, const char * szFunc, void * &pOut)
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
	
	BOOL bRet1 = WriteProcessMemory(hProc, pTargetBase, pLocalBase, pOldOptHeader->SizeOfImage, nullptr);
	BOOL bRet2 = WriteProcessMemory(hProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr);
	BOOL bRet3 = WriteProcessMemory(hProc, pFunc, ManualMapShell, ShellSize, nullptr);
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

	DWORD dwRet = StartRoutine(hProc, pFunc, pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, CC_STDCALL, LastError, hOut);
	
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
		void * pK32 = ReCa<void*>(GetModuleHandleA("kernel32.dll"));
		WriteProcessMemory(hProc, pTargetBase, pK32, 0x1000, nullptr);
	}

	return dwRet;
}

DWORD Cloaking(HANDLE hProc, DWORD Flags, HINSTANCE hMod, DWORD & LastError)
{
	if (!Flags)
		return INJ_ERR_SUCCESS;

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

		PEB	peb{ 0 };
		if (!ReadProcessMemory(hProc, ppeb, &peb, sizeof(PEB), nullptr))
		{
			LastError = GetLastError();
			return INJ_ERR_CANT_ACCESS_PEB;
		}

		PEB_LDR_DATA ldrdata{ 0 };
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

				BYTE Buffer[MAX_PATH * 4]{ 0 };
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
	if (!pData || !pData->pLoadLibraryExW)
		return NULL;

	HINSTANCE hDll	= pData->pLoadLibraryExW(pData->szDll, nullptr, NULL);
	pData->hRet		= hDll;

	pData->pLoadLibraryExW = nullptr;

	return pData->hRet;
}

DWORD LoadLibraryShell_End() { return 0; }

HINSTANCE __stdcall LdrLoadDllShell(LDR_LOAD_DLL_DATA * pData)
{
	if (!pData || !pData->pLdrLoadDll)
		return NULL;

	pData->pModuleFileName.szBuffer = ReCa<wchar_t*>(pData->Data);
	pData->ntRet = pData->pLdrLoadDll(nullptr, 0, &pData->pModuleFileName, &pData->hRet);

	pData->pLdrLoadDll = nullptr;

	return ReCa<HINSTANCE>(pData->hRet);
}

DWORD LdrLoadDllShell_End() { return 1; }

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

	pData->hRet	= ReCa<HINSTANCE>(pBase);

	return pData->hRet;
}

DWORD ManualMapShell_End() { return 2; }