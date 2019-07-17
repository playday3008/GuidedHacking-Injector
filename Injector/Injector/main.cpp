#include "Injection.h"
#include <string>

DWORD dwError = ERROR_SUCCESS;

bool SetPrivilegeA(const char * szPrivilege, bool bState = true)
{
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		dwError = GetLastError();
		return false;
	}

	TOKEN_PRIVILEGES TokenPrivileges	= { 0 };
	TokenPrivileges.PrivilegeCount		= 1;
	TokenPrivileges.Privileges[0].Attributes = bState ? SE_PRIVILEGE_ENABLED : 0;

	if (!LookupPrivilegeValueA(nullptr, szPrivilege, &TokenPrivileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		CloseHandle(hToken);
		return false;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		dwError = GetLastError();
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);

	return true;
}

void ErrorMsg(DWORD Err1, DWORD Err2)
{
	char szRet[9]{ 0 };
	char szAdv[9]{ 0 };
	wsprintfA(szRet, "%08X", Err1);
	wsprintfA(szAdv, "%08X", Err2);
	std::string Msg = "Error code: 0x";
	Msg += szRet;
	Msg += "\nAdvanced info: 0x";
	Msg += szAdv;

	MessageBoxA(0, Msg.c_str(), "Injection failed", MB_ICONERROR);
}

bool VerifyFile(const char * szDllFile)
{
	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	auto FileSize = File.tellg();
	if (FileSize <= 0x1000)
	{
		File.close();
		return false;
	}

	BYTE * pHeader = new BYTE[0x1000];

	if (!pHeader)
	{
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pHeader), 0x1000);
	File.close();
	
	auto * pNtHeader	= ReCa<IMAGE_NT_HEADERS*>(pHeader + ReCa<IMAGE_DOS_HEADER*>(pHeader)->e_lfanew);
	WORD e_magic	= ReCa<IMAGE_DOS_HEADER*>(pHeader)->e_magic;
	DWORD Signature	= pNtHeader->Signature;
	WORD Machine	= pNtHeader->FileHeader.Machine;

	delete[] pHeader;

	if (e_magic != 0x5A4D || Signature != 0x4550) //MZ & PE
		return false;
	
	#ifdef _WIN64
	if (Machine != IMAGE_FILE_MACHINE_AMD64)
		return false;
	#else
	if (Machine != IMAGE_FILE_MACHINE_I386)
		return false;
	#endif

	return true;
}

bool VerifyPlatform(HANDLE hProc)
{
	BOOL bTarget = FALSE;
	IsWow64Process(hProc, &bTarget);

	BOOL bOwn = FALSE;
	IsWow64Process(GetCurrentProcess(), &bOwn);

	return (bTarget == bOwn);
}

int main(UINT argc, char * argv[])
{
	if (argc < 5)
	{
		ErrorMsg(INJ_ERR_INVALID_ARGC, argc);
		return 0;
	}
	
	char * szDll			= nullptr;
	DWORD PID				= 0;
	DWORD Flags				= 0;
	DWORD InjectionMethod	= 0;
	DWORD LaunchMethod		= 0;

	for (UINT i = 1; i < argc; ++i)
	{
		if (!lstrcmpA(argv[i], "/p") || !lstrcmpA(argv[i], "/P"))
		{
			if (i + 1 < argc)
				PID = strtoul(argv[i + 1], nullptr, 10);
			else
				return 0;

			i++;
		}
		else if (!lstrcmpA(argv[i], "/f") || !lstrcmpA(argv[i], "/F"))
		{
			if (i + 1 < argc)
				szDll = argv[i + 1];
			else
				return 0;

			i++;
		}
		else if (!lstrcmpA(argv[i], "/m") || !lstrcmpA(argv[i], "/M"))
		{
			if (i + 1 < argc)
			{
				DWORD val = strtoul(argv[i + 1], nullptr, 10);
				if (val <= 2)
					InjectionMethod = val;
				else
					InjectionMethod = 0;
			}
			else
				return 0;

			i++;
		}
		else if (!lstrcmpA(argv[i], "/o") || !lstrcmpA(argv[i], "/O"))
		{
			if (i + 1 < argc)
			{
				DWORD val = strtoul(argv[i + 1], nullptr, 10);
				if (val > INJ_MAX_FLAGS)
					Flags = 0;
				else
					Flags = val;
			}
			else
				return 0;

			i++;
		}
		else if (!lstrcmpA(argv[i], "/l") || !lstrcmpA(argv[i], "/L"))
		{
			if (i + 1 < argc)
			{
				DWORD val = strtoul(argv[i + 1], nullptr, 10);
				if (val <= 2)
					LaunchMethod = val;
				else
					LaunchMethod = 0;
			}
			else
				return 0;

			i++;
		}
	}
	
	INJECTION_MODE	im = (INJECTION_MODE)InjectionMethod;
	LAUNCH_METHOD	lm = (LAUNCH_METHOD)LaunchMethod;

	if(!PID)
	{
		ErrorMsg(INJ_ERR_INVALID_PID, PID);
		return 0;
	}

	SetPrivilegeA("SeDebugPrivilege", true);
	
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		ErrorMsg(INJ_ERR_CANT_OPEN_PROCESS, GetLastError());
		return 0;
	}

	if (!VerifyPlatform(hProc))
	{
		ErrorMsg(INJ_ERR_INVALID_TARGET_ARCH, 0);
		return 0;
	}

	if (!VerifyFile(szDll))
	{
		CloseHandle(hProc);
		ErrorMsg(INJ_ERR_INVALID_DLL_FILE, 0);
		return 0;
	}
	
	DWORD Err = 0;
	DWORD Ret = 0;

	Ret = InjectDLL(szDll, hProc, im, lm, Flags, &Err);

	CloseHandle(hProc);

	if (Ret)
	{
		ErrorMsg(Ret, Err);
	}	

	return ERROR_SUCCESS;
}