#pragma once

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

enum _PROCESSINFOCLASS
{
	ProcessBasicInformation
};
typedef _PROCESSINFOCLASS PROCESSINFOCLASS;

enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5,
	SystemHandleInformation = 16
};
typedef _SYSTEM_INFORMATION_CLASS SYSTEM_INFORMATION_CLASS;

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	WORD UniqueProcessId;
	WORD CreateBackTraceIndex;
	BYTE ObjectTypeIndex;
	BYTE HandleAttributes;
	WORD HandleValue;
	void * Object;
	ULONG GrantedAccess;
};
typedef SYSTEM_HANDLE_TABLE_ENTRY_INFO SYSTEM_HANDLE_TABLE_ENTRY_INFO;

struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
};
typedef _SYSTEM_HANDLE_INFORMATION SYSTEM_HANDLE_INFORMATION;

enum THREAD_STATE
{
    Running = 2,
    Waiting = 5,
};

typedef enum _KWAIT_REASON
{
	Executive			= 0,
	FreePage			= 1,
	PageIn				= 2,
	PoolAllocation		= 3,
	DelayExecution		= 4,
	Suspended			= 5,
	UserRequest			= 6,
	WrExecutive			= 7,
	WrFreePage			= 8,
	WrPageIn			= 9,
	WrPoolAllocation	= 10,
	WrDelayExecution	= 11,
	WrSuspended			= 12,
	WrUserRequest		= 13,
	WrEventPair			= 14,
	WrQueue				= 15,
	WrLpcReceive		= 16,
	WrLpcReply			= 17,
	WrVirtualMemory		= 18,
	WrPageOut			= 19,
	WrRendezvous		= 20,
	WrCalloutStack		= 25,
	WrKernel			= 26,
	WrResource			= 27,
	WrPushLock			= 28,
	WrMutex				= 29,
	WrQuantumEnd		= 30,
	WrDispatchInt		= 31,
	WrPreempted			= 32,
	WrYieldExecution	= 33,
	WrFastMutex			= 34,
	WrGuardedMutex		= 35,
	WrRundown			= 36,
	MaximumWaitReason	= 37
} KWAIT_REASON;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID		ClientId;
	KPRIORITY		Priority;
	LONG			BasePriority;
	ULONG			ContextSwitches;
	THREAD_STATE	ThreadState;
	KWAIT_REASON	WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	WorkingSetPrivateSize;
	ULONG			HardFaultCount;
	ULONG			NumberOfThreadsHighWatermark;
	ULONGLONG		CycleTime;
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	KPRIORITY		BasePriority;
	HANDLE			UniqueProcessId;
	HANDLE			InheritedFromUniqueProcessId;
	ULONG			HandleCount;
	ULONG			SessionId;
	ULONG_PTR		UniqueProcessKey;
	SIZE_T			PeakVirtualSize;
	SIZE_T			VirtualSize;
	ULONG			PageFaultCount;
	SIZE_T 			PeakWorkingSetSize;
	SIZE_T			WorkingSetSize;
	SIZE_T			QuotaPeakPagedPoolUsage;
	SIZE_T 			QuotaPagedPoolUsage;
	SIZE_T 			QuotaPeakNonPagedPoolUsage;
	SIZE_T 			QuotaNonPagedPoolUsage;
	SIZE_T 			PagefileUsage;
	SIZE_T 			PeakPagefileUsage;
	SIZE_T 			PrivatePageCount;
	LARGE_INTEGER	ReadOperationCount;
	LARGE_INTEGER	WriteOperationCount;
	LARGE_INTEGER	OtherOperationCount;
	LARGE_INTEGER 	ReadTransferCount;
	LARGE_INTEGER	WriteTransferCount;
	LARGE_INTEGER	OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


using f_NtCreateThreadEx			= NTSTATUS(__stdcall*)(HANDLE * pHandle, ACCESS_MASK DesiredAccess, void * pAttr, HANDLE hProc, void * pFunc, void * pArg,
										ULONG Flags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, void * pAttrListOut);
using f_LdrLoadDll					= NTSTATUS(__stdcall*)(wchar_t * szOptPath, ULONG ulFlags, UNICODE_STRING * pModuleFileName, HANDLE * pOut);
using f_NtQueryInformationProcess	= NTSTATUS(__stdcall*)(HANDLE hProc, PROCESSINFOCLASS PIC, void * pBuffer, ULONG BufferSize, ULONG * SizeOut);
using f_NtQuerySystemInformation	= NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS SIC, void * pBuffer, ULONG BufferSize, ULONG * SizeOut);