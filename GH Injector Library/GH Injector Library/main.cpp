#include "Injection.h"

HINSTANCE g_hInjMod = NULL;

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hDll);
		g_hInjMod = hDll;
	}

	return TRUE;
}