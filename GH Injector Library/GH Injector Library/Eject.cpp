#include "Eject.h"

void EjectDll(HANDLE hProc, HINSTANCE hModBase)
{
	void * pFreeLibrary = nullptr;
	GetImportA(hProc, "kernel32.dll", "FreeLibrary", pFreeLibrary);

	if (!pFreeLibrary)
		return;

	DWORD win32			= 0;
	HINSTANCE hDummy	= NULL;
	StartRoutine(hProc, pFreeLibrary, reinterpret_cast<void*>(hModBase), LM_NtCreateThreadEx, true, CC_STDCALL, win32, hDummy);
}