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
	_ultoa_s(Err1, szRet, 0x10);
	_ultoa_s(Err2, szAdv, 0x10);
	std::string Msg = "Error code: 0x";
	Msg += szRet;
	Msg += "\nAdvanced info: 0x";
	Msg += szAdv;

	MessageBoxA(0, Msg.c_str(), "Injection failed", MB_ICONERROR);
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

	SetPrivilegeA("SeDebugPrivilege", true);

	DWORD Err = 0;
	DWORD Ret = 0;
	if (PID)
	{
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
		if (!hProc)
		{
			ErrorMsg(INJ_ERR_CANT_OPEN_PROCESS, GetLastError());
			return 0;
		}

		Ret = InjectDLL(szDll, hProc, im, lm, Flags, &Err);
		CloseHandle(hProc);

		if (Ret)
		{
			ErrorMsg(Ret, Err);
		}
	}
	else
	{
		ErrorMsg(INJ_ERR_INVALID_PID, PID);
		return 0;
	}

	return ERROR_SUCCESS;
}