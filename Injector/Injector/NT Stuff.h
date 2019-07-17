#pragma once

#ifndef NT_STUFF_H
#define NT_STUFF_H

#include <Windows.h>

#ifndef NT_FAIL
	#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(status) (status >= 0)
#endif

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 4

struct UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
};

struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrder;
	LIST_ENTRY		InMemoryOrder;
	LIST_ENTRY		InInitOrder;
	void *			DllBase;
	void *			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;
};

struct PEB_LDR_DATA
{
	ULONG		Length;
	BYTE		Initialized;
	HANDLE		SsHandle;
	LIST_ENTRY	InLoadOrderModuleListHead;
	LIST_ENTRY	InMemoryOrderModuleListHead;
	LIST_ENTRY	InInitializationOrderModuleListHead;
	void *		EntryInProgress;
	BYTE		ShutdownInProgress;
	HANDLE		ShutdownThreadId;
};

struct PEB
{
	void * Reserved[3];
	PEB_LDR_DATA * Ldr;
};

struct PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PEB *		pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
};

struct SECTION_INFO
{
	WORD Len;
	WORD MaxLen;
	wchar_t * szData;
	BYTE pData[MAX_PATH * 2];
};
// NtQueryVirtualMemory: MemoryMappedFilenameInformation

enum _PROCESSINFOCLASS
{
	ProcessBasicInformation
};
typedef _PROCESSINFOCLASS PROCESSINFOCLASS;

enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation = 0,
	MemoryMappedFilenameInformation = 2
};
typedef _MEMORY_INFORMATION_CLASS MEMORY_INFORMATION_CLASS;
typedef _MEMORY_INFORMATION_CLASS MEMORYINFOCLASS;

using f_NtCreateThreadEx			= NTSTATUS(__stdcall*)(HANDLE * pHandle, ACCESS_MASK DesiredAccess, void * pAttr, HANDLE hProc, void * pFunc, void * pArg,
										ULONG Flags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, void * pAttrListOut);
using f_LdrLoadDll					= NTSTATUS(__stdcall*)(wchar_t * szOptPath, ULONG ulFlags, UNICODE_STRING * pModuleFileName, HANDLE * pOut);
using f_NtQueryInformationProcess	= NTSTATUS(__stdcall*)(HANDLE hProc, PROCESSINFOCLASS PIC, void * pBuffer, ULONG BufferSize, ULONG * SizeOut);
using f_NtQueryVirtualMemory		= NTSTATUS(__stdcall*)(HANDLE hProc, void * pAddress, MEMORYINFOCLASS MIC, void * pBuffer, SIZE_T BufferSize, SIZE_T * SizeOut);

#endif