/*
 * Copyright 2010 coderebasoft
 *
 * This file is part of netmon.
 *
 * netmon is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * netmon is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with netmon.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __BALANCE_NETMON_FILTER_H__
#define __BALANCE_NETMON_FILTER_H__

#ifndef __WIN32

#define IO_SENDING_SIZE_INIT_VALUE_LOW 0xFFFFFFFF
#define IO_SENDING_SIZE_INIT_VALUE_HIGH 0x7FFFFFFF
#define PROCESS_NETWORK_TRAFFIC_INIT_REFERRENCE 2
#define COMMON_OBJ_NAME_MAX_LENGTH 0x400
#define TDI_EVENT_CONTEXT_MARK 0xFEC02B00
#define TDI_FILTER_LOOKASIDE_POOL_TAG 0x74636576
#define TDI_FILTER_TIMER_ELAPSE_TIME -10000000 //1 second
#define WAIT_CONFIGURED_PROC_TIME -100000 //10 milli second
#define SHORT_PATH_SIGN L'~'
#define PATH_DELIM L'\\'
#define CONST_STRING_SIZE( const_str ) ( DWORD )( sizeof( const_str ) - sizeof( const_str[ 0 ] ) )
#define FILE_SYMBLOLIC_NAME_PREFIX L"\\??\\\\:\\"
#define FILE_SYMBLOLIC_NAME_PREFIX_SIZE CONST_STRING_SIZE( FILE_SYMBLOLIC_NAME_PREFIX )

#endif

#define PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH 300
#define MAX_PATH 260
#define SYSTEM_IDLE_PROCESS_ID 0
#define SYSTEM_SYSTEM_PROCESS_ID 4

#define IRP_PROCESS_INFO 0x01
#define PROCESS_IO_OUTPUT_INFO 0x02
#define IO_INTERNAL_CONTROL_INFO 0x04
#define IRP_COMPLETION_INFO 0x08
#define TIMER_DPC_INFO 0x10
#define PROCESS_NEW_IO_INFO 0x20
#define DRIVER_UNLOAD_INFO 0x40
#define PROCESS_IRP_LIST_INFO 0x80
#define PROCESS_START_THREAD_INFO 0x0100
#define IO_CONTROL_INFO 0x0200
#define RECV_EVENT_HANDLER_INFO 0x0400
#define SEND_SPEED_CONTROL_INFO 0x0800
#define CLEANUP_INFO 0x1000
#define OUTPUT_ALL_PROCESS_IO_INFO 0x2000
#define OUTPUT_ALL_PROCESS_CONTROL_INFO 0x4000
#define RESTORE_EVENT_HANDLER_INFO 0x0008000
#define ADD_PROCESS_CONTROL_INFO 0x00010000
#define SYNC_SEND_IRP_PROCESS_INFO 0x00020000
#define RELEASE_PROCESS_INFO 0x00040000
#define READ_USER_PROC_PEB_INFO 0x00080000
#define DRIVER_ENTRY_INFO 0x00100000
#define IRP_CANCEL_INFO 0x00200000
#define PROCESS_COMMON_INFO 0x80000000

#define BP_ON_GET_ALL_PROCESS_IO 0x01
#define BP_ON_GET_ALL_PROCESS_CONTROL 0x02
#define BP_ON_ADD_PROCESS_CONTROL 0x04

//#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
//    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
//)
#define IOCTL_SELF_PROTECT_NOTIFY CTL_CODE( FILE_DEVICE_UNKNOWN, 0x101, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_GET_TDI_FILTER_DRIVER_VERSION CTL_CODE( FILE_DEVICE_UNKNOWN, 0x102, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_GET_ALL_PROCESS_IO_INFO CTL_CODE( FILE_DEVICE_UNKNOWN, 0x103, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_OPEN_FILTERING CTL_CODE( FILE_DEVICE_UNKNOWN, 0x104, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_CLOSE_FILTERING CTL_CODE( FILE_DEVICE_UNKNOWN, 0x105, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_CHECK_FILTERING_STATE CTL_CODE( FILE_DEVICE_UNKNOWN, 0x106, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_GET_ALL_TRAFFIC CTL_CODE( FILE_DEVICE_UNKNOWN, 0x107, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_TDI_START_UPDATE_PROCESS_IO_INFO CTL_CODE( FILE_DEVICE_UNKNOWN, 0x201, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_GET_ALL_PROCESS_INFO CTL_CODE( FILE_DEVICE_UNKNOWN, 0x202, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_RELEASE_ALL_PROCESS_INFO CTL_CODE( FILE_DEVICE_UNKNOWN, 0x203, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_SET_DEBUG_TRACE_FLAG CTL_CODE( FILE_DEVICE_UNKNOWN, 0x204, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_TDI_SET_BP_FLAG CTL_CODE( FILE_DEVICE_UNKNOWN, 0x205, METHOD_BUFFERED, FILE_ANY_ACCESS )

#ifndef __WIN32
typedef unsigned char BYTE, *PBYTE;
typedef unsigned long DWORD, *PDWORD;
typedef int BOOL;
typedef void *LPVOID;
typedef CONNECTION_CONTEXT *PCONNECTION_CONTEXT;
#define CALLBACK __stdcall

ULONG DebugPrintEx( DWORD dwFlags, CHAR *Format, ... );

#ifdef _DEBUG
#define DEBUG_PRINT( x ) DebugPrintEx x
#else
#define DEBUG_PRINT( x )
#endif

typedef NTSTATUS 
  ( *ClientEventReceive )(
  PVOID  TdiEventContext,
  CONNECTION_CONTEXT  ConnectionContext,
  ULONG  ReceiveFlags,
  ULONG  BytesIndicated,
  ULONG  BytesAvailable,
  ULONG  *BytesTaken,
  PVOID  Tsdu,
  PIRP  *IoRequestPacket
  );

typedef NTSTATUS ( *ClientEventChainedReceive )(
    IN PVOID  TdiEventContext,
    IN CONNECTION_CONTEXT  ConnectionContext,
    IN ULONG  ReceiveFlags,
    IN ULONG  ReceiveLength,
    IN ULONG  StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID  TsduDescriptor
    );

typedef NTSTATUS ( *ClientEventReceiveDatagram )(
	IN PVOID  TdiEventContext,
	IN LONG  SourceAddressLength,
	IN PVOID  SourceAddress,
	IN LONG  OptionsLength,
	IN PVOID  Options,
	IN ULONG  ReceiveDatagramFlags,
	IN ULONG  BytesIndicated,
	IN ULONG  BytesAvailable,
	OUT ULONG  *BytesTaken,
	IN PVOID  Tsdu,
	OUT PIRP  *IoRequestPacket
	);

NTKERNELAPI NTSTATUS 
  ZwQueryDirectoryFile(
    HANDLE  FileHandle,
    HANDLE  Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID  ApcContext,
    PIO_STATUS_BLOCK  IoStatusBlock,
    PVOID  FileInformation,
    ULONG  Length,
    FILE_INFORMATION_CLASS  FileInformationClass,
    BOOLEAN  ReturnSingleEntry,
    PUNICODE_STRING  FileName,
    BOOLEAN  RestartScan
    );

NTKERNELAPI PEPROCESS IoThreadToProcess(
  PETHREAD Thread
);

NTKERNELAPI BOOLEAN
  IoIsOperationSynchronous(
    PIRP  Irp
	);

NTKERNELAPI HANDLE
  PsGetProcessId(
    PEPROCESS  Process
    );

NTKERNELAPI NTSTATUS
  PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS *Process
    );

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef VOID ( *PPEBLOCKROUTINE)(PVOID);
#endif

#include <PshPack1.h>

typedef struct __PROCESS_IO_INFO_OUTPUT
{
	DWORD dwProcessId;
	LARGE_INTEGER AllSuccSendedDataSize;
	LARGE_INTEGER AllSuccRecvedDataSize;
	BOOL bStopSend;
	BOOL bStopRecv;
	LARGE_INTEGER SendingSpeed;
	LARGE_INTEGER SuccSendedDataSizeOnce;
	LARGE_INTEGER SuccRecvedDataSizeOnce;
} PROCESS_IO_INFO_OUTPUT, *PPROCESS_IO_INFO_OUTPUT;

#ifndef __WIN32
typedef struct _IMAGE_FIXUP_ENTRY {
	USHORT        Offset:12;
	USHORT        Type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

//typedef enum _PROCESS_IMFORMATION_CLASS {
//	ProcessBasicInformation,
//	ProcessQuotaLimits,
//	ProcessIoCounters,
//	ProcessVmCounters,
//	ProcessTimes,
//	ProcessBasePriority,
//	ProcessRaisePriority,
//	ProcessDebugPort,
//	ProcessExceptionPort,
//	ProcessAccessToken,
//	ProcessLdtInformation,
//	ProcessLdtSize,
//	ProcessDeaultHardErrorMode,
//	ProcessIoPortHandlers,
//	ProcessPooledUsageAndLimits,
//	ProcessWorkingSetWatch,
//	ProcessUserModeIOPL,
//	ProcessEnableAlignmentFaultFixup,
//	ProcessPriorityClass,
//	ProcessWx86Information,
//	ProcessHandleCount,
//	ProcessAffinityMask,
//	ProcessPriorityBoost,
//	ProcessDeviceMap,
//	ProcessSessionInformation,
//	ProcessForegroundInformation,
//	ProcessWow64Information
//} PROCESS_INFORMATION_CLASS;

//typedef enum _KPROFILE_SOURCE {
//	ProfileTime,
//	ProfileAlignmentFixup,
//	ProfileTotalIssues,
//	ProfilePipelineDry,
//	ProfileLoadInstructions,
//	ProfilePipelineFrozen,
//	ProfileBranchInstructions,
//	ProfileTotalNonissues,
//	ProfileDcacheMisses,
//	ProfileIcacheMisses,
//	ProfileCacheMisses,
//	ProfileBranchMispredictions,
//	ProfileStoreInstructions,
//	ProfileFpInstructions,
//	ProfileIntegerInstructions,
//	Profile2Issue,
//	Profile3Issue,
//	Profile4Issue,
//	ProfileSpecialInstructions,
//	ProfileTotalCycles,
//	ProfileIcacheIssues,
//	ProfileDcacheAccesses,
//	ProfileMemoryBarrierCycles,
//	ProfileLoadLinkedIssues,
//	ProfileMaximum
//} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef struct _SECTION_BASIC_INFORMATION {
	PVOID BaseAddress;
	ULONG Attributes;
	LARGE_INTEGER Size;
}SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID                  *KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID                  *ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID                  **ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, *PPEB;

typedef enum __SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowersInformation,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;


extern NTSTATUS NTAPI ZwQuerySystemInformation( 
	SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation, 
	ULONG SystemInformationLength, 
	PULONG ReturnLength
);

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION{
	ULONG NextEntryOffset; 
	ULONG Unknown; 
	LARGE_INTEGER CreationTime; 
	LARGE_INTEGER LastAccessTime; 
	LARGE_INTEGER LastWriteTime; 
	LARGE_INTEGER ChangeTime; 
	LARGE_INTEGER EndOfFile; 
	LARGE_INTEGER AllocationSize; 
	ULONG FileAttributes; 
	ULONG FileNameLength; 
	ULONG EaInformationLength; 
	UCHAR AlternateNameLength; 
	WCHAR AlternateName[12]; 
	WCHAR FileName[1]; 
} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION;   

typedef struct __DELETE_PROCESS_IO_INFO_PARAM
{
	DWORD dwParantId;
	DWORD dwProcessId;
	BOOL bCreate;
} DELETE_PROCESS_IO_INFO_PARAM, *PDELETE_PROCESS_IO_INFO_PARAM;

#endif

//#define MAX_PROCESS_IMAGE_PATH_LEN 512
typedef struct __PROCESS_INFORMATION_RECORD
{
	WCHAR szNativeImageFileName[ PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH ];
	WCHAR szImageFileName[ MAX_PATH ];
	BOOL bRemove;
	BOOL bStopSend;
	BOOL bStopRecv;
	LARGE_INTEGER SendingSpeed;
} PROCESS_INFORMATION_RECORD, *PPROCESS_INFORMATION_RECORD;

#ifndef __WIN32

typedef struct __PROCESS_NETWORK_TRAFFIC
{
	LIST_ENTRY ProcessIoList;
	PEPROCESS pEProcess;
	DWORD dwProcessId;
	LARGE_INTEGER AllSuccSendedDataSize;
	LARGE_INTEGER AllSuccRecvedDataSize;
	LARGE_INTEGER AllSuccSendedDataSizePrev;
	LARGE_INTEGER AllSuccRecvedDataSizePrev;
	LARGE_INTEGER SuccSendedDataSizeOnce;
	LARGE_INTEGER SuccRecvedDataSizeOnce;
	LARGE_INTEGER SendedSizeOneSec;
	BOOL bStopSend;
	BOOL bStopRecv;
	LARGE_INTEGER SendingSpeed;
	PKTIMER pTimer;
	PKDPC pDpc;
	KSPIN_LOCK IrpListLock;
	LIST_ENTRY IrpList;
	LIST_ENTRY ListEntry;
	DWORD dwRefCount;
	BOOL bCancel;
} PROCESS_NETWORK_TRAFFIC, *PPROCESS_NETWORK_TRAFFIC;

typedef struct __PROCESS_INFORMATION_LIST_ENTRY
{
	LIST_ENTRY ListEntry;
	PPROCESS_INFORMATION_RECORD pProcessInformation;
} PROCESS_INFORMATION_LIST_ENTRY, *PPROCESS_INFORMATION_LIST_ENTRY;

typedef struct __TDI_EVENT_CONTEXT_WRAP
{
	DWORD dwEventContextMark;
	DWORD dwEventType;
	PVOID pOrgEventHandler;
	PVOID pOrgEventContext;
	PEPROCESS pEProcess;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	PFILE_OBJECT pAssocAddr;
	PDEVICE_OBJECT pDeviceObject;
} TDI_EVENT_HANDLER_WRAP, *PTDI_EVENT_HANDLER_WRAP;

typedef struct __TDI_EVENT_HANDLER_LINK
{
	LIST_ENTRY List;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrap;
} TDI_EVENT_HANDLER_LIST, *PTDI_EVENT_HANDLER_LIST;

typedef struct __TDI_COMPLETION_WRAP
{
	LIST_ENTRY ListEntry;
	CHAR bSendOpera;
	CHAR bWrap;
	CHAR bAssocIrp;
	CHAR bSync;
	PIO_COMPLETION_ROUTINE pCompletionRoutine;
	LPVOID pContext;
	CHAR Control;
	PEPROCESS pEProcess;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
} TDI_COMPLETION_WRAP, *PTDI_COMPLETION_WRAP;

typedef struct __TDI_FILTER_DEVICE_EXTENSION
{
	PDEVICE_OBJECT pTdiDeviceObject;
} TDI_FILTER_DEVICE_EXTENSION, *PTDI_FILTER_DEVICE_EXTENSION;

typedef struct __IO_COUNTERSEX
{
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} IO_COUNTERSEX, *PIO_COUNTERSEX;

typedef struct __SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER WaitTime;
	DWORD StartAddress;
	CLIENT_ID ClientId;
	DWORD Priority;
	DWORD BasePriority;
	DWORD ContextSwitchCount;
	DWORD /*THREAD_STATE*/ State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct __SYSTEM_PROCESSES
{
	DWORD NextEntryDelta;
	DWORD ThreadCount;
	DWORD Reserved1[ 6 ];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	DWORD BasePriority;
	DWORD ProcessId;
	DWORD InheritedFromProcessId;
	DWORD HandleCount;
	DWORD Reserved2[ 2 ];
	VM_COUNTERS VmCounters;
	IO_COUNTERSEX IoCounters;
	SYSTEM_THREADS Threads;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;
#endif

#include <PopPack.h>
#endif