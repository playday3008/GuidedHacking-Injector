#pragma once

#include "NT Stuff.h"
#include <Windows.h>
#include <TlHelp32.h>

bool GetImportA(HANDLE hProc, char * szDll, char * szFunc, void * &pOut);