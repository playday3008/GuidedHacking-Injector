#include <Windows.h>
#include <fstream>
#include <Psapi.h>
#include <vector>
#include <strsafe.h>

#pragma comment(lib, "Psapi.lib")

#ifdef _WIN64
#define FILENAME L"\\SWHEX64.txt"
#else
#define FILENAME L"\\SWHEX86.txt"
#endif

#define SWHEX_ERR_SUCCESS			0x00000000
#define SWHEX_ERR_CANT_OPEN_FILE	0x30000001
#define SWHEX_ERR_EMPTY_FILE		0x30000002
#define SWHEX_ERR_INVALID_INFO		0x30000003
#define SWHEX_ERR_ENUM_WINDOWS_FAIL 0x30000004
#define SWHEX_ERR_NO_WINDOWS		0x30000005

struct HookData
{
	HHOOK	m_hHook;
	HWND	m_hWnd;
};

struct EnumWindowsCallback_Data
{
	std::vector<HookData>	m_HookData;
	DWORD					m_PID;
	HOOKPROC				m_pHook;
	HINSTANCE				m_hModule;
};

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);

int main()
{
	wchar_t InfoPath[MAX_PATH * 2]{ 0 };
	GetModuleFileNameW(GetModuleHandleW(nullptr), InfoPath, sizeof(InfoPath) / sizeof(InfoPath[0]));

	size_t size_out = 0;
	StringCchLengthW(InfoPath, MAX_PATH * 2, &size_out);

	wchar_t * pInfoEnd = InfoPath;
	pInfoEnd += size_out;
	while (*pInfoEnd-- != '\\');
	*(pInfoEnd + 2)= 0;

	StringCbCatW(InfoPath, sizeof(InfoPath), FILENAME);

	std::ifstream File;
	File.open(InfoPath, std::ios::ate);
	if (File.rdstate() & std::ifstream::failbit)
	{
		return SWHEX_ERR_CANT_OPEN_FILE;
	}

	auto FileSize = File.tellg();
	if (!FileSize)
	{
		File.close();
		return SWHEX_ERR_EMPTY_FILE;
	}

	File.seekg(0, std::ios::beg);

	char * info = new char[static_cast<size_t>(FileSize)];
	File.read(info, FileSize);

	File.close();

	DeleteFileW(InfoPath);

	char * pszPID = info;
	while (*info++ != '!');
	info[-1] = '\0';
	char * pszHook = info;

	DWORD ProcID = strtol(pszPID, &info, 10);
#ifdef _WIN64
	UINT_PTR pHook = strtoll(pszHook, &info, 0x10);
#else
	DWORD pHook = strtol(pszHook, &info, 0x10);
#endif
	
	if (!ProcID || !pHook)
	{
		return SWHEX_ERR_INVALID_INFO;
	}

	EnumWindowsCallback_Data data;
	data.m_PID		= ProcID;
	data.m_pHook	= reinterpret_cast<HOOKPROC>(pHook);
	data.m_hModule	= GetModuleHandleW(L"kernel32.dll");

	if (!EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&data)))
	{
		return SWHEX_ERR_ENUM_WINDOWS_FAIL;
	}

	if (data.m_HookData.empty())
	{
		return SWHEX_ERR_NO_WINDOWS;
	}

	for (auto i : data.m_HookData)
	{
		SetForegroundWindow(i.m_hWnd);
		SendMessageW(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(10);
		SendMessageW(i.m_hWnd, WM_KEYUP, VK_SPACE, 0);
		UnhookWindowsHookEx(i.m_hHook);
	}

	return SWHEX_ERR_SUCCESS;
}

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	auto * pData = reinterpret_cast<EnumWindowsCallback_Data*>(lParam);
	DWORD PID = pData->m_PID;
	
	DWORD winPID = 0;
	DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);
	if (winPID == PID)
	{
		wchar_t szWindow[MAX_PATH]{ 0 };
		if (IsWindowVisible(hWnd) && GetWindowTextW(hWnd, szWindow, MAX_PATH))
		{
			if (GetClassNameW(hWnd, szWindow, MAX_PATH) && wcscmp(szWindow, L"ConsoleWindowClass"))
			{
				HHOOK hHook = SetWindowsHookExA(WH_CALLWNDPROC, pData->m_pHook, pData->m_hModule, winTID);
				if (hHook)
				{
					pData->m_HookData.push_back({ hHook, hWnd });
				}
			}
		}
	}

	return TRUE;
}