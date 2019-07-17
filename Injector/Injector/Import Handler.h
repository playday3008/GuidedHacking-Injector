#pragma once

#ifndef IMPORT_HANDLER_H
#define IMPORT_HANDLER_H

#include <Windows.h>
#include <Psapi.h>
#include "NT Stuff.h"

BYTE * GetProcAddressA(HINSTANCE hDll, char * szFunc);
bool GetImportA(HANDLE hProc, char * szDll, char * szFunc, void * &pOut);
bool AddressToModuleBase(HANDLE hProc, BYTE * &pAddress);

#endif