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

#include <strsafe.h>
#include "common.h"
#include <tdikrnl.h>
#include "hash.h"


#include "netmon_.h"

extern volatile KSYSTEM_TIME KeTickCount;
extern POBJECT_TYPE *IoFileObjectType;

DWORD TDI_FILTER_DRIVER_VERSION[] = { 1, 0, 0, 0006 };

#define UDP_DEVICE_NAME L"\\Device\\Udp"
#define TCP_DEVICE_NAME L"\\Device\\Tcp"

#define TDI_FILTER_DEVICE_DOS_NAME L"\\DosDevices\\BCTdiFilter"
#define TDI_FILTER_DEVICE_NAME L"\\Device\\BCTdiFilter"

#define DOS_DEVICE_NAME_PREFIX L"\\??\\"

#define TICK_COUNT_RECORD_INIT_VAL 0xBB40E64E
#define TICK_COUNT_RECORD_NOT_INIT_VAL 0x44BF19B1

PKTHREAD ThreadUpdateConfig = NULL;
PKTHREAD ThreadProcessIrp = NULL;

PDEVICE_OBJECT g_FilterDeviceForDeviceTcp = NULL;
PDEVICE_OBJECT g_FilterDeviceForDeviceUdp = NULL;
PDEVICE_OBJECT g_DevTdiFilter = NULL; 

BOOL g_bThreadsRunning = FALSE;
BOOL g_bBeginStartThreads = FALSE;

DWORD g_dwTickCountFactor = TICK_COUNT_RECORD_INIT_VAL;
DWORD g_dwTickCountFactorNot = TICK_COUNT_RECORD_NOT_INIT_VAL;

#define MASTER_IRP_HASH_TABLE_SIZE 500
hash_table g_MasterIrpHash;

BOOL g_bFiltering = TRUE;

BOOL g_bThreadUpdateConfigStop = FALSE;
BOOL g_bThreadIrpProcessStop = FALSE;

LARGE_INTEGER Interval;

LARGE_INTEGER g_SendingDelayTime = { 0 };
LARGE_INTEGER g_TimerElapse = { 0 };
LARGE_INTEGER g_ThreadWaitConfigProcTime = { 0 };
LARGE_INTEGER g_WaitNewIistItemTime = { 0 };

LARGE_INTEGER g_AllSendedDataSize;
LARGE_INTEGER g_AllRecvedDataSize;

KSPIN_LOCK g_SpLockProcessNetWorkTrafficInfo;
KSPIN_LOCK g_SpLockTdiEventHandlerInfo;

KEVENT g_EventProcessInformationAdded;
KEVENT g_EventIrpListAdded;
KEVENT g_EventCompletion;
//KEVENT g_EventTimerExit;

ERESOURCE g_SyncResource;

NPAGED_LOOKASIDE_LIST g_CompletionWrapList;

LIST_ENTRY g_TdiEventHandlerInfoList;
LIST_ENTRY g_ProcessIoInfoList;
LIST_ENTRY g_ProcessInformationList;

#define __thiscall __cdecl

BOOL IsDriverDevice( PDEVICE_OBJECT pDeviceObject ); 

NTSTATUS  TdiFilterChainedRecvHandler(
    IN PVOID  TdiEventContext,
    IN CONNECTION_CONTEXT  ConnectionContext,
    IN ULONG  ReceiveFlags,
    IN ULONG  ReceiveLength,
    IN ULONG  StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID  TsduDescriptor
    );

NTSTATUS  TdiFilterRecvDatagramEventHandler(
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

DWORD dwBPFlag = 0;
DWORD dwPrintFlags = IRP_CANCEL_INFO |DRIVER_ENTRY_INFO | DRIVER_UNLOAD_INFO; // | READ_USER_PROC_PEB_INFO | IRP_COMPLETION_INFO | RELEASE_PROCESS_INFO | SEND_SPEED_CONTROL_INFO | SYNC_SEND_IRP_PROCESS_INFO; IO_CONTROL_INFO | PROCESS_IRP_LIST_INFO | PROCESS_START_THREAD_INFO; //RECV_EVENT_HANDLER_INFO | RESTORE_EVENT_HANDLER_INFO;/*PROCESS_START_THREAD_INFO | *//*SEND_SPEED_CONTROL_INFO | RECV_EVENT_HANDLER_INFO | IRP_COMPLETION_INFO | DRIVER_UNLOAD_INFO | IO_INTERNAL_CONTROL_INFO;*/ //PROCESS_NEW_IO_INFO | IO_INTERNAL_CONTROL_INFO | DRIVER_UNLOAD_INFO | ;

ULONG DebugPrintEx( DWORD dwFlags, CHAR *Format, ... )
{
	ULONG uRet;
	va_list va;

	if( !( dwPrintFlags & dwFlags ) )
	{
		return 0;
	}

	va_start( va, Format );

	uRet = vDbgPrintEx( 0xFFFFFFFF, 0, Format, va );

	va_end( va );

	return uRet;
}

#define DEL_EVENT_WRAP 1
#define GET_EVENT_WRAP 2

BOOL g_StopWaitCompletion = FALSE;
INT32 g_CompletionIrpCount = 0;
PKTHREAD g_ThreadWaitCompletion = NULL;
PIRP DequeueIrp( PLIST_ENTRY pListHead, PKSPIN_LOCK SpLock );
VOID TdiFilterCancel( 
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp 
    );
VOID ThreadWaitCompletion( PVOID pParam );
NTSTATUS RestoreEventHandler( PTDI_EVENT_HANDLER_WRAP pEventHandlerWrap );
DWORD ReleaseAllEventHandlerWrap();
VOID ReleaseAllProcessNetWorkTrafficInfo();
NTSTATUS  TdiFilterCompletion( PDEVICE_OBJECT pDeviceObject, PIRP pIrp, LPVOID pContext );
NTSTATUS TdiFilterSyncSendProcess( PROCESS_NETWORK_TRAFFIC *pProcessNetWorkTrafficInfo, 
								 PDEVICE_OBJECT pDeviceObject, 
								 PIRP pIrp );
//KDEFERRED_ROUTINE TimerDpcProcess;
VOID ThreadSendingSpeedControl( PVOID pParam );
VOID TimerDpcProcess( PKDPC pDpc, PVOID pEProcess, PVOID SystemArgument1 , PVOID SystemArgument2 );
VOID DeleteProcessIoInfo( DWORD dwParentId, DWORD dwProcessId, BOOL bCreate );
NTSTATUS GetAllProcessesIoInformation( LPVOID *pOutput, DWORD dwInputBuffLength, DWORD *pAllInfoLength );
NTSTATUS GetAllProcessesInformation( PPROCESS_INFORMATION_RECORD pAllProcessInfomation, DWORD dwBufferLength, DWORD *pAllInfoLength );
NTSTATUS ReleaseAllProcessesInformation();
VOID DeleteEventWrap( PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList );
VOID UpdateEventHandlerWrap( PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo,
							PEPROCESS pEProcess,
							PDEVICE_OBJECT pDeviceObject, 
							PFILE_OBJECT pFileObject, 
							DWORD dwEventType, 
							PVOID pEventHandler,
							PVOID pEventContext, 
							PTDI_EVENT_HANDLER_LIST *ppEventHandlerWrap, 
							DWORD dwFlags );
VOID ThreadUpdateProcessIoState( PVOID pParam );

NTSTATUS TdiFilterRecvEventHandler( IN PVOID  TdiEventContext,
									  IN CONNECTION_CONTEXT  ConnectionContext,
									  IN ULONG  ReceiveFlags,
									  IN ULONG  BytesIndicated,
									  IN ULONG  BytesAvailable,
									  OUT ULONG  *BytesTaken,
									  IN PVOID  Tsdu,
									  OUT PIRP  *IoRequestPacket
									  );
VOID TdiFilterUnload( PDRIVER_OBJECT pDriverObject );
NTSTATUS TdiFilterCleanUp(PDEVICE_OBJECT DeviceObject, PIRP pIrp );
NTSTATUS TdiFilterDefaultIrpProcess( PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS StartWorkThreadManageProcessInfo( 
	PROCESS_INFORMATION_RECORD *pProcessInformationFind, 
	DWORD dwInputBufferLength 
	);
NTSTATUS TdiFilterInternalIoControl( PDEVICE_OBJECT pDeviceObject, PIRP pIrp );
NTSTATUS TdiFilterIoControl( PDEVICE_OBJECT pDeviceObject, PIRP pIrp );
NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath );
NTSTATUS AttachToTdiDevice( PDRIVER_OBJECT DriverObject, PUNICODE_STRING TargetDeviceName, PDEVICE_OBJECT *DeviceObject );
PPROCESS_NETWORK_TRAFFIC  GetProcessNetWorkTrafficInfoFromEProcess( PEPROCESS pEProcess );
PPROCESS_NETWORK_TRAFFIC  ReferenceProcessNetWorkTrafficInfo( PEPROCESS pEProcess );
DWORD  ReleaseProcessNetWorkTrafficInfo( PROCESS_NETWORK_TRAFFIC *pProcessIoInformaiton );
NTSTATUS  EnterUserProcessReadImagePath( PEPROCESS pEProcess, PUNICODE_STRING pImageFilePath );
NTSTATUS  GetFileHandle( PHANDLE pFileHandle, PUNICODE_STRING FileName );
NTSTATUS  QueryFileAndDirInfo( HANDLE hFile, 
									  LPCWSTR pwszFilePath, 
									  LPCWSTR pwszFileName, 
									  PFILE_BOTH_DIRECTORY_INFORMATION FileInformation, 
									  ULONG FileInformationLength );
LPWSTR  FindWideCharInWideString(LPCWSTR pszwString, DWORD dwLength, WCHAR wFindChar);
NTSTATUS  ShortPathNameToEntirePathName( PUNICODE_STRING ShortPathName, PUNICODE_STRING FullPathName );
NTSTATUS  GetProcessImagePath( DWORD dwProcessId, PUNICODE_STRING ProcessImageFilePath, DWORD dwBufferLen );
NTSTATUS RegisterProcessCreateNotify(); 
NTSTATUS DeregisterProcessCreateNotify(); 

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif
			/*	NTSTATUS 
			PsCreateSystemThread(
			OUT PHANDLE  ThreadHandle,
			IN ULONG  DesiredAccess,
			IN POBJECT_ATTRIBUTES  ObjectAttributes  OPTIONAL,
			IN HANDLE  ProcessHandle  OPTIONAL,
			OUT PCLIENT_ID  ClientId  OPTIONAL,
			IN PKSTART_ROUTINE  StartRoutine,
			IN PVOID  StartContext
			);*/

NTSTATUS CreateWorkThread( PKSTART_ROUTINE StartRoutine, PVOID StartContext, PKTHREAD *kThread )
{
	NTSTATUS ntStatus;
	HANDLE hThread;

	ASSERT( NULL != kThread );

	*kThread = NULL;
	hThread = NULL;

	ntStatus = PsCreateSystemThread( &hThread, 
		THREAD_ALL_ACCESS, 
		NULL, 
		NULL, 
		NULL, 
		StartRoutine, 
		NULL 
		);

	if( !NT_SUCCESS( ntStatus ) )
	{
		goto RETURN_;
	}

	ntStatus = ObReferenceObjectByHandle( 
		hThread, 
		THREAD_ALL_ACCESS, 
		NULL, 
		KernelMode, 
		( PVOID* )kThread, 
		NULL 
		);

	if( !NT_SUCCESS( ntStatus ) )
	{
		goto RETURN_;
	}

RETURN_:
	if( NULL != hThread )
	{
		ZwClose( hThread );
	}

	return ntStatus;
}

NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath )
{
	NTSTATUS ntStatus;
	INT32 i;

	UNICODE_STRING TcpDeviceName;
	UNICODE_STRING UdpDeviceName;

	UNICODE_STRING TdiFilterDeviceName;
	UNICODE_STRING TdiFilterDeviceDosName;

	DebugPrintEx( DRIVER_ENTRY_INFO, "netmon enter DriverEntry\n" );

	RtlInitUnicodeString( ( PUNICODE_STRING )&TdiFilterDeviceName, 
		TDI_FILTER_DEVICE_NAME );

	RtlInitUnicodeString( ( PUNICODE_STRING )&TdiFilterDeviceDosName, 
		TDI_FILTER_DEVICE_DOS_NAME );

	DebugPrintEx( DRIVER_ENTRY_INFO, "netmon DriverEntry begin IoCreateDevice TdiFilterDeviceName\n" );
	ntStatus = IoCreateDevice(
		DriverObject, 
		0, 
		&TdiFilterDeviceName, 
		FILE_DEVICE_UNKNOWN, 
		0, 
		FALSE, 
		&g_DevTdiFilter 
		);

	DebugPrintEx( DRIVER_ENTRY_INFO, "netmon DriverEntry end IoCreateDevice TdiFilterDeviceName\n" );

	if ( !NT_SUCCESS( ntStatus ) )
	{
		return ntStatus;
	}

	DebugPrintEx( DRIVER_ENTRY_INFO, "netmon DriverEntry begin IoCreateSymbolicLink TdiFilterDeviceDosName\n" );

	ntStatus = IoCreateSymbolicLink( &TdiFilterDeviceDosName, 
		&TdiFilterDeviceName );

	if( !NT_SUCCESS( ntStatus ) )
	{
		goto Error;
	}

	KeInitializeSpinLock( &g_SpLockProcessNetWorkTrafficInfo );
	KeInitializeSpinLock( &g_SpLockTdiEventHandlerInfo );

	InitializeListHead( &g_ProcessIoInfoList );
	InitializeListHead( &g_TdiEventHandlerInfoList );
	InitializeListHead( &g_ProcessInformationList );

	ExInitializeResourceLite(&g_SyncResource);
		
	KeInitializeEvent( &g_EventProcessInformationAdded, SynchronizationEvent, 0 );
	KeInitializeEvent( &g_EventIrpListAdded, SynchronizationEvent, 0 );
	KeInitializeEvent( &g_EventCompletion, SynchronizationEvent, 0 );
		
	g_TimerElapse.LowPart = TDI_FILTER_TIMER_ELAPSE_TIME;
	g_TimerElapse.HighPart = 0xFFFFFFFF;
		
	g_SendingDelayTime.LowPart = -10000;
	g_SendingDelayTime.HighPart = 0xFFFFFFFF;
		
	g_WaitNewIistItemTime.LowPart = TDI_FILTER_TIMER_ELAPSE_TIME;
	g_WaitNewIistItemTime.HighPart = 0xFFFFFFFF;

	g_ThreadWaitConfigProcTime.LowPart = WAIT_CONFIGURED_PROC_TIME;
	g_ThreadWaitConfigProcTime.HighPart = 0xFFFFFFFF;

	ExInitializeNPagedLookasideList( 
		&g_CompletionWrapList, 
		NULL, 
		NULL, 
		0, 
		sizeof( TDI_COMPLETION_WRAP ),
		TDI_FILTER_LOOKASIDE_POOL_TAG, 
		0
		);

	for( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i ++ )
	{
		DriverObject->MajorFunction[ i ] = TdiFilterDefaultIrpProcess;
	}
	
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = TdiFilterIoControl;
	DriverObject->MajorFunction[ IRP_MJ_INTERNAL_DEVICE_CONTROL ] = TdiFilterInternalIoControl;
	DriverObject->MajorFunction[ IRP_MJ_CLEANUP ] = TdiFilterCleanUp;
	DriverObject->DriverUnload = TdiFilterUnload;
	
	RtlInitUnicodeString( &TcpDeviceName, TCP_DEVICE_NAME );
	RtlInitUnicodeString( &UdpDeviceName, UDP_DEVICE_NAME );

	if( !NT_SUCCESS( AttachToTdiDevice( DriverObject, &TcpDeviceName, &g_FilterDeviceForDeviceTcp ) ) || 
		!NT_SUCCESS( AttachToTdiDevice( DriverObject, &UdpDeviceName, &g_FilterDeviceForDeviceUdp ) ) )
	{
		ExDeleteNPagedLookasideList( &g_CompletionWrapList );
		goto Error;

	}

	ntStatus = RegisterProcessCreateNotify();
	if( !NT_SUCCESS( ntStatus ) )
	{
		ExDeleteNPagedLookasideList( &g_CompletionWrapList );
		goto Error;
	}

	ntStatus = CreateWorkThread( ThreadWaitCompletion, NULL, &g_ThreadWaitCompletion );
	if( !NT_SUCCESS( ntStatus ) )
	{
		ExDeleteNPagedLookasideList( &g_CompletionWrapList );
		goto Error;
	}

	DebugPrintEx( DRIVER_ENTRY_INFO, "netmon DriverEntry end CreateWorkThread ThreadWaitCompletion\n" );

	ntStatus = init_hash_table( &g_MasterIrpHash, MASTER_IRP_HASH_TABLE_SIZE );
	if( 0 > ntStatus )
	{
		goto Error;
	}

	return ntStatus;

Error:
	if ( NULL != g_FilterDeviceForDeviceTcp )
	{
		PDEVICE_OBJECT DeviceObject;
		DeviceObject = *( PDEVICE_OBJECT * )g_FilterDeviceForDeviceTcp->DeviceExtension;
		IoDetachDevice( DeviceObject );
		IoDeleteDevice( g_FilterDeviceForDeviceTcp );
		g_FilterDeviceForDeviceTcp = NULL;
	}
	
	if ( NULL != g_FilterDeviceForDeviceUdp )
	{
		PDEVICE_OBJECT DeviceObject;
		DeviceObject = *( PDEVICE_OBJECT * )g_FilterDeviceForDeviceUdp->DeviceExtension;
		IoDetachDevice( DeviceObject );
		IoDeleteDevice( g_FilterDeviceForDeviceUdp );
		g_FilterDeviceForDeviceUdp = NULL;
	}

	if( NULL != g_DevTdiFilter )
	{
		IoDeleteDevice( g_DevTdiFilter );
		g_DevTdiFilter = NULL;
	}

	IoDeleteSymbolicLink( &TdiFilterDeviceDosName );
	return ntStatus;
}

DWORD ReleaseAllEventHandlerWrap()
{
	NTSTATUS ntStatus;
	DWORD dwErrorCount;
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PLIST_ENTRY pListEntryPrev;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrap;

	KeAcquireSpinLock( &g_SpLockTdiEventHandlerInfo, &OldIrql );

	pListEntry = g_TdiEventHandlerInfoList.Flink;

	dwErrorCount = 0;

	for( ; ; )
	{
		if( pListEntry == &g_TdiEventHandlerInfoList )
		{
			break;
		}

		pListEntryPrev = pListEntry->Flink;

		pTdiEventHandlerList = ( PTDI_EVENT_HANDLER_LIST )pListEntry;

		RemoveEntryList( pListEntry );

		ntStatus = RestoreEventHandler( pTdiEventHandlerList->pTdiEventHandlerWrap );
		if( !NT_SUCCESS( ntStatus ) )
		{
			dwErrorCount ++;
		}

		ExFreePoolWithTag( pTdiEventHandlerList->pTdiEventHandlerWrap, 0 );
		ExFreePoolWithTag( pTdiEventHandlerList, 0 );

		pListEntry = pListEntryPrev;
	}

	KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
	return dwErrorCount;
}

VOID TdiFilterUnload( PDRIVER_OBJECT pDriverObject )
{
	//UNICODE_STRING TcpDeviceName;
	//UNICODE_STRING UdpDeviceName;

	//UNICODE_STRING TdiFilterDeviceName;
	UNICODE_STRING TdiFilterDeviceDosName;

	PDEVICE_OBJECT DeviceObject;

	KdBreakPoint();

	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon enter TdiFilterUnload\n" );

	//RtlInitUnicodeString( ( PUNICODE_STRING )&TdiFilterDeviceName, 
	//	TDI_FILTER_DEVICE_NAME );

	RtlInitUnicodeString( ( PUNICODE_STRING )&TdiFilterDeviceDosName, 
		TDI_FILTER_DEVICE_DOS_NAME );

	//RtlInitUnicodeString( &TcpDeviceName, TCP_DEVICE_NAME );
	//RtlInitUnicodeString( &UdpDeviceName, UDP_DEVICE_NAME );

	g_bFiltering = FALSE;

	DeregisterProcessCreateNotify();

	ASSERT( NULL != g_FilterDeviceForDeviceTcp && 
		NULL != g_FilterDeviceForDeviceUdp &&
		NULL != g_DevTdiFilter );

	if( NULL != g_FilterDeviceForDeviceTcp )
	{
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release g_FilterDeviceForDeviceTcp begin\n" );
		DeviceObject = *( PDEVICE_OBJECT * )g_FilterDeviceForDeviceTcp->DeviceExtension;
		IoDetachDevice( DeviceObject );
		IoDeleteDevice( g_FilterDeviceForDeviceTcp );
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release g_FilterDeviceForDeviceTcp end\n" );
	}

	if( NULL != g_FilterDeviceForDeviceUdp )
	{
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release g_FilterDeviceForDeviceUdp begin\n" );
		DeviceObject = *( PDEVICE_OBJECT * )g_FilterDeviceForDeviceUdp->DeviceExtension;
		IoDetachDevice( DeviceObject );
		IoDeleteDevice( g_FilterDeviceForDeviceUdp );
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release g_FilterDeviceForDeviceUdp end\n" );
	}

	if( NULL != g_DevTdiFilter )
	{
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release g_DevTdiFilter begin\n" );
		IoDeleteDevice( g_DevTdiFilter );
		IoDeleteSymbolicLink( &TdiFilterDeviceDosName );
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release g_DevTdiFilter end\n" );
	}

	ASSERT( NULL != g_ThreadWaitCompletion );

	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ReleaseAllProcessesInformation begin\n" );
	ReleaseAllProcessesInformation();
	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ReleaseAllProcessesInformation end\n" );

	g_bThreadUpdateConfigStop = TRUE;
	g_bThreadIrpProcessStop = TRUE;

	if( NULL != ThreadUpdateConfig )
	{
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release ThreadUpdateConfig begin\n" );
		KeWaitForSingleObject( ThreadUpdateConfig, Executive, KernelMode, FALSE, NULL );
		ObDereferenceObject( ThreadUpdateConfig );
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release ThreadUpdateConfig end\n" );
	}

	if( NULL != ThreadProcessIrp )
	{
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release ThreadProcessIrp begin\n" );
		KeWaitForSingleObject( ThreadProcessIrp, Executive, KernelMode, FALSE, NULL );
		ObDereferenceObject( ThreadProcessIrp );
		DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon release ThreadProcessIrp end\n" );
	}

	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ReleaseAllEventHandlerWrap begin\n" );
	ReleaseAllEventHandlerWrap();
	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ReleaseAllEventHandlerWrap end\n" );

	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ReleaseAllProcessNetWorkTrafficInfo begin\n" );
	ReleaseAllProcessNetWorkTrafficInfo();
	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ReleaseAllProcessNetWorkTrafficInfo end\n" );

	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon wait g_ThreadWaitCompletion begin\n" );
	KeSetEvent( &g_EventCompletion, 0, FALSE );
	KeWaitForSingleObject( g_ThreadWaitCompletion, Executive, KernelMode, FALSE, NULL );
	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon wait g_ThreadWaitCompletion end\n" );

	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ExDeleteNPagedLookasideList begin\n" );
	ExDeleteNPagedLookasideList( &g_CompletionWrapList );
	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ExDeleteNPagedLookasideList end\n" );

	ExDeleteResourceLite( &g_SyncResource );
	DebugPrintEx( DRIVER_UNLOAD_INFO, "netmon ExDeleteResourceLite end\n" );

	return;
}

NTSTATUS TdiFilterCleanUp(PDEVICE_OBJECT DeviceObject, PIRP pIrp )
{
	NTSTATUS ntStatus;
	KIRQL OldIrql;
	LIST_ENTRY *pListEntry;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerListFind;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrapFind;
	PFILE_OBJECT pFileObject;

	TDI_FILTER_DEVICE_EXTENSION *pDeviceExtension;
	PIO_STACK_LOCATION pIrpSp;

	//KdBreakPoint();
	DebugPrintEx( CLEANUP_INFO, "netmon Enter TdiFilterCleanUp\n" );
	pDeviceExtension = ( TDI_FILTER_DEVICE_EXTENSION* )DeviceObject->DeviceExtension;
	pIrpSp = IoGetCurrentIrpStackLocation( pIrp );
	pFileObject = pIrpSp->FileObject;

	if( FALSE == IsDriverDevice( DeviceObject ) )
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto COMPLETE_IRP;
	}

	if( DeviceObject == g_DevTdiFilter )
	{
		ntStatus = STATUS_SUCCESS;
		goto COMPLETE_IRP;
	}

	//pIrp->Flags == IRP_CLOSE_OPERATION 
	//IRP_SYNCHRONOUS_API

	DebugPrintEx( CLEANUP_INFO,"netmon TdiFilterCleanUp IoCallDriver\n" );
	IoSkipCurrentIrpStackLocation( pIrp );
	ntStatus = IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

	if( !NT_SUCCESS( ntStatus ) )
	{
		DebugPrintEx( CLEANUP_INFO,"netmon TdiFilterCleanUp IoCallDriver return ERROR\n" );
		return ntStatus;
	}

	KeAcquireSpinLock( &g_SpLockTdiEventHandlerInfo, &OldIrql );

FIND_LIST_AGAIN:
	pListEntry = g_TdiEventHandlerInfoList.Flink;

	for( ; ; )
	{
		if( pListEntry == &g_TdiEventHandlerInfoList )
		{
			break;
		}

		pTdiEventHandlerListFind = ( PTDI_EVENT_HANDLER_LIST )pListEntry;
		pTdiEventHandlerWrapFind = pTdiEventHandlerListFind->pTdiEventHandlerWrap;

		DebugPrintEx( CLEANUP_INFO,"Client address find: 0x%0.8x, input 0x%0.8x \n", 
			pTdiEventHandlerWrapFind->pAssocAddr, 
			pFileObject );

		if( pTdiEventHandlerWrapFind->pAssocAddr == pFileObject )
		{
			DebugPrintEx( CLEANUP_INFO,"Client address finded: 0x%0.8x \n", pTdiEventHandlerWrapFind->pAssocAddr );

			RemoveEntryList( pListEntry );

			ExFreePoolWithTag( pTdiEventHandlerWrapFind, 0 );
			ExFreePoolWithTag( pTdiEventHandlerListFind, 0 );
			goto FIND_LIST_AGAIN;
		}

		pListEntry = pListEntry->Flink;
	}

	KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
	return ntStatus;

COMPLETE_IRP:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest( pIrp, 0 );

	return ntStatus;
}

NTSTATUS  TdiFilterDefaultIrpProcess( PDEVICE_OBJECT pDeviceObject, PIRP pIrp )
{
	IO_STACK_LOCATION *pIrpSp;
	NTSTATUS ntStatus;
	TDI_FILTER_DEVICE_EXTENSION *pDeviceExtension;

	DebugPrintEx( PROCESS_COMMON_INFO, "netmon enter TdiFilterDefaultIrpProcess \n" );
	pDeviceExtension = ( TDI_FILTER_DEVICE_EXTENSION* )pDeviceObject->DeviceExtension;

	pIrpSp = IoGetCurrentIrpStackLocation( pIrp );

	if ( !IsDriverDevice( pDeviceObject, pIrp ) )
	{
		ntStatus  = STATUS_INVALID_PARAMETER;
		goto COMPLETE_IRP;
	}

	if ( pDeviceObject == g_DevTdiFilter )
	{
		ntStatus = STATUS_SUCCESS;
		goto COMPLETE_IRP;
	}

	IoSkipCurrentIrpStackLocation( pIrp );
	return IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

COMPLETE_IRP:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IofCompleteRequest( pIrp, 0 );
	return ntStatus;
}
 
NTSTATUS RestoreEventHandler( PTDI_EVENT_HANDLER_WRAP pEventHandlerWrap )
{
	NTSTATUS ntStatus;
	PIRP pIrp = NULL;
	PDEVICE_OBJECT pDeviceObject;

	ASSERT( NULL != pEventHandlerWrap );

	ASSERT( FALSE != MmIsAddressValid( pEventHandlerWrap ) );
	pDeviceObject = pEventHandlerWrap->pDeviceObject;

	ASSERT( FALSE != MmIsAddressValid( pDeviceObject ) );

	if( NULL == pDeviceObject || 
		FALSE == MmIsAddressValid( pEventHandlerWrap->pAssocAddr ) )
		return STATUS_UNSUCCESSFUL;

	if( NULL == pEventHandlerWrap->pOrgEventHandler )
	{
		return STATUS_SUCCESS;
	}

	pIrp = TdiBuildInternalDeviceControlIrp( TDI_SET_EVENT_HANDLER, pDeviceObject, 
		pEventHandlerWrap->pAssocAddr, NULL, NULL );
	
	if ( NULL == pIrp )
	{
		ntStatus = STATUS_UNSUCCESSFUL;
		goto RETURN_;
	}

	TdiBuildSetEventHandler( pIrp, 
		pDeviceObject, 
		pEventHandlerWrap->pAssocAddr, 
		NULL, 
		NULL, 
		pEventHandlerWrap->dwEventType,
		pEventHandlerWrap->pOrgEventHandler, 
		pEventHandlerWrap->pOrgEventContext 
		);

	DebugPrintEx( RESTORE_EVENT_HANDLER_INFO, "net RestoreEventHandler restore event wrap 0x%0.8x, handler 0x%0.8x file object 0x%0.8x success \n", 
		pEventHandlerWrap, 
		pEventHandlerWrap->pOrgEventHandler,
		pEventHandlerWrap->pAssocAddr );

	ntStatus = IoCallDriver( pDeviceObject, pIrp );
	pIrp = NULL;

	if( NT_SUCCESS( ntStatus ) ) {
		//ASSERT( FALSE );
		DebugPrintEx( RESTORE_EVENT_HANDLER_INFO, "net RestoreEventHandler restore event wrap 0x%0.8x, handler 0x%0.8x success \n", 
			pEventHandlerWrap, 
			pEventHandlerWrap->pOrgEventHandler
			);
		goto RETURN_;
	}

	// don't wait to complete

RETURN_:
	if( NULL != pIrp )
	{
		IoFreeIrp( pIrp );
	}

	return ntStatus;
}

VOID DeleteEventWrap( PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList )
{
	KIRQL OldIrql;

	KeAcquireSpinLock( &g_SpLockTdiEventHandlerInfo, &OldIrql );

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "Delete event wrap list: 0x%0.8x \n", 
		pTdiEventHandlerList );

	RemoveEntryList( ( PLIST_ENTRY )pTdiEventHandlerList );

	ExFreePoolWithTag( pTdiEventHandlerList->pTdiEventHandlerWrap, 0 );
	ExFreePoolWithTag( pTdiEventHandlerList, 0 );

	KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
	return;
}

VOID UpdateEventHandlerWrap( PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo, 
							PEPROCESS pEProcess,
							PDEVICE_OBJECT pDeviceObject, 
							PFILE_OBJECT pFileObject, 
							DWORD dwEventType, 
							PVOID pEventHandler,
							PVOID pEventContext, 
							PTDI_EVENT_HANDLER_LIST *ppEventHandlerList, 
							DWORD dwFlags )
{
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerListFind;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrapFind;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerListNew = NULL;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrapNew = NULL;

	ASSERT( NULL != ppEventHandlerList );

	*ppEventHandlerList = NULL;

	KeAcquireSpinLock( &g_SpLockTdiEventHandlerInfo, &OldIrql );

	pListEntry = g_TdiEventHandlerInfoList.Flink;

	for( ; ; )
	{
		if( pListEntry == &g_TdiEventHandlerInfoList )
		{
			break;
		}

		pTdiEventHandlerListFind = ( PTDI_EVENT_HANDLER_LIST )pListEntry;
		pTdiEventHandlerWrapFind = pTdiEventHandlerListFind->pTdiEventHandlerWrap;

		if( pTdiEventHandlerWrapFind->pAssocAddr == pFileObject &&
			pTdiEventHandlerWrapFind->dwEventType == dwEventType )
		{

			ASSERT( TRUE == MmIsAddressValid( pTdiEventHandlerWrapFind->pAssocAddr ) );
			if( pProcessNetWorkTrafficInfo != NULL && 
				pTdiEventHandlerWrapFind->pProcessNetWorkTrafficInfo != pProcessNetWorkTrafficInfo )
			{
				DebugPrintEx( RECV_EVENT_HANDLER_INFO, "***Find event handler wrap, but process is not same***, finded 0x%0.8x, input 0x%0.8x \n", 
					pTdiEventHandlerWrapFind->pProcessNetWorkTrafficInfo, 
					pProcessNetWorkTrafficInfo );
			}

			if( DEL_EVENT_WRAP == dwFlags )
			{
				DebugPrintEx( RECV_EVENT_HANDLER_INFO, "Delete event wrap: 0x%0.8x, Process io information 0x%0.8x, Address 0x%0.8x, event type %d, event handler 0x%0.8x \n", 
					pTdiEventHandlerWrapFind,  
					pProcessNetWorkTrafficInfo, 
					pFileObject, 
					pTdiEventHandlerWrapFind->dwEventType,
					pTdiEventHandlerWrapFind->pOrgEventHandler 
					);
				RemoveEntryList( pListEntry );
				ExFreePoolWithTag( pTdiEventHandlerWrapFind, 0 );
				ExFreePoolWithTag( pTdiEventHandlerListFind, 0 );
			}
			else
			{
				DebugPrintEx( RECV_EVENT_HANDLER_INFO, "Update event wrap: 0x%0.8x, Process io information 0x%0.8x, Address 0x%0.8x old event type %d, old event handler 0x%0.8x, new event type %d, new event handler 0x%0.8x \n", 
					pTdiEventHandlerWrapFind,  
					pProcessNetWorkTrafficInfo, 
					pFileObject, 
					pTdiEventHandlerWrapFind->dwEventType,
					pTdiEventHandlerWrapFind->pOrgEventHandler, 
					dwEventType, 
					pEventHandler );

				pTdiEventHandlerWrapFind->pOrgEventHandler = pEventHandler;
				pTdiEventHandlerWrapFind->pOrgEventContext = pEventContext;

				*ppEventHandlerList = pTdiEventHandlerListFind;
			}

			KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
			return;
		}

		pListEntry = pListEntry->Flink;
	}

	if( GET_EVENT_WRAP == dwFlags )
	{
		pTdiEventHandlerWrapNew = ( PTDI_EVENT_HANDLER_WRAP )AllocZeroPoolWithTag( NonPagedPool, sizeof( TDI_EVENT_HANDLER_WRAP ) );
		if( NULL == pTdiEventHandlerWrapNew )
		{
			goto RELEASE_POOL_EXIT;
		}

		pTdiEventHandlerListNew = ( PTDI_EVENT_HANDLER_LIST )AllocZeroPoolWithTag( NonPagedPool, sizeof( TDI_EVENT_HANDLER_LIST ) );
		if( NULL == pTdiEventHandlerListNew )
		{
			goto RELEASE_POOL_EXIT;
		}

		pTdiEventHandlerWrapNew->dwEventContextMark = TDI_EVENT_CONTEXT_MARK;
		pTdiEventHandlerWrapNew->dwEventType = dwEventType;
		pTdiEventHandlerWrapNew->pOrgEventHandler = pEventHandler;
		pTdiEventHandlerWrapNew->pOrgEventContext = pEventContext;
		pTdiEventHandlerWrapNew->pEProcess = pEProcess;
		pTdiEventHandlerWrapNew->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;
		pTdiEventHandlerWrapNew->pAssocAddr = pFileObject;
		pTdiEventHandlerWrapNew->pDeviceObject = pDeviceObject;

		pTdiEventHandlerListNew->pTdiEventHandlerWrap = pTdiEventHandlerWrapNew;

		InsertTailList( &g_TdiEventHandlerInfoList, ( PLIST_ENTRY )pTdiEventHandlerListNew );

		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "Add new event wrap: 0x%0.8x, Process io information 0x%0.8x, Address 0x%0.8x event type %d, new event handler 0x%0.8x \n", 
			pTdiEventHandlerWrapNew, 
			pProcessNetWorkTrafficInfo, 
			pFileObject, 
			pTdiEventHandlerWrapNew->dwEventType, 
			pTdiEventHandlerWrapNew->pOrgEventHandler 
			);

		*ppEventHandlerList = pTdiEventHandlerListNew;

		KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
		return;

RELEASE_POOL_EXIT:
		if( NULL != pTdiEventHandlerWrapNew )
		{
			ExFreePoolWithTag( pTdiEventHandlerWrapNew, NonPagedPool );
		}

		if( NULL != pTdiEventHandlerListNew )
		{
			ExFreePoolWithTag( pTdiEventHandlerListNew, NonPagedPool );
		}

		KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
		return;
	}

	KeReleaseSpinLock( &g_SpLockTdiEventHandlerInfo, OldIrql );
	return;
}

PIRP DequeueIrp( PLIST_ENTRY pListHead, PKSPIN_LOCK SpLock )
{
	KIRQL oldIrql;
	PIRP nextIrp = NULL;

	KeAcquireSpinLock( SpLock, &oldIrql );

	while( !nextIrp && !IsListEmpty( pListHead ) )
	{
		PDRIVER_CANCEL oldCancelRoutine;
		PLIST_ENTRY listEntry = RemoveHeadList( pListHead );

		// Get the next IRP off the queue.
		nextIrp = CONTAINING_RECORD( listEntry, IRP, Tail.Overlay.ListEntry );

		if( NULL == nextIrp->AssociatedIrp.MasterIrp )
		{
			//  Clear the IRP's cancel routine
			oldCancelRoutine = IoSetCancelRoutine(nextIrp, NULL);
			//  IoCancelIrp() could have just been called on this IRP.
			//  What we're interested in is not whether IoCancelIrp() was called (nextIrp->Cancel flag set),
			//  but whether IoCancelIrp() called (or is about to call) our cancel routine.
			//  To check that, check the result of the test-and-set macro IoSetCancelRoutine.
			if (oldCancelRoutine){
				//  Cancel routine not called for this IRP.  Return this IRP.
				ASSERT(oldCancelRoutine == TdiFilterCancel );
			}
			else {
				//  This IRP was just canceled and the cancel routine was (or will be) called.
				//  The cancel routine will complete this IRP as soon as we drop the spin lock,
				//  so don't do anything with the IRP.
				//  Also, the cancel routine will try to dequeue the IRP, 
				//  so make the IRP's listEntry point to itself.
				ASSERT(nextIrp->Cancel);
				InitializeListHead(&nextIrp->Tail.Overlay.ListEntry);
				nextIrp = NULL;
			}
		}
	}

	KeReleaseSpinLock(SpLock, oldIrql);

	return nextIrp;
}

VOID TdiFilterCancel( 
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp 
    )

{
	NTSTATUS ntStatus;
	PLIST_ENTRY pListEntry = NULL;
	PIRP pAssocIrp = NULL;
	KIRQL OldIrql;
	KIRQL CancelIrql = Irp->CancelIrql;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTraffic = NULL;
	hash_key key;
	key.quad_part = make_hash_key( 0, ( DWORD )Irp );

	KdBreakPoint();

	DebugPrintEx( IRP_CANCEL_INFO, "netmon Enter TdiFilterCancel\n" );
	IoReleaseCancelSpinLock( CancelIrql );

FIND_ASSOC_IRPS:

	KeAcquireSpinLock( &pProcessNetWorkTraffic->IrpListLock, &OldIrql );

	DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCancel get_hash_value\n" );
	ntStatus = get_hash_value( &g_MasterIrpHash, key, &pProcessNetWorkTraffic );
	DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCancel get_hash_value return 0x%0.8x, pProcessNetWorkTraffic 0x%0.8x\n", 
		ntStatus, 
		pProcessNetWorkTraffic 
		);

	if( 0 > ntStatus )
	{
		ASSERT( FALSE );
		goto RETURN_;
	}

	ASSERT( TRUE == MmIsAddressValid( pProcessNetWorkTraffic ) );

	pListEntry = pProcessNetWorkTraffic->IrpList.Flink;

	for ( ; ; ) 
	{
		if( pListEntry == &pProcessNetWorkTraffic->IrpList )
		{
			break;
		}

		pAssocIrp = CONTAINING_RECORD( pListEntry, IRP, Tail.Overlay.ListEntry );
		DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCancel find irp 0x%0.8x master irp 0x%0.8x cancel irp 0x%0.8x\n", 
			pAssocIrp->AssociatedIrp.MasterIrp,
			Irp );

		if ( Irp == pAssocIrp->AssociatedIrp.MasterIrp )
		{
			DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCancel finded \n" );
			RemoveEntryList( &pAssocIrp->Tail.Overlay.ListEntry );
			KeReleaseSpinLock(  &pProcessNetWorkTraffic->IrpListLock, OldIrql ); 

			pAssocIrp->IoStatus.Status = STATUS_CANCELLED;
			pAssocIrp->IoStatus.Information = 0;
			
			IoCompleteRequest( pAssocIrp, IO_NO_INCREMENT );
			goto FIND_ASSOC_IRPS;
		}
		pListEntry = pListEntry->Flink;
	} 

	RemoveEntryList( &Irp->Tail.Overlay.ListEntry );
	KeReleaseSpinLock(  &pProcessNetWorkTraffic->IrpListLock, OldIrql ); 

	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCancel delete hash item 0x%0.8x \n", 
		Irp );
	//KdBreakPoint();
	ntStatus = del_hash_item( &g_MasterIrpHash, key, &pProcessNetWorkTraffic );

	DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCancel delete hash item 0x%0.8x, return 0x%0.8x \n", 
		Irp, 
		ntStatus );

	return;
	//ASSERT( 0 <= ntStatus );

RETURN_:
	KeReleaseSpinLock( &pProcessNetWorkTraffic->IrpListLock, OldIrql ); 
}

NTSTATUS TdiFilterInternalIoControl( PDEVICE_OBJECT pDeviceObject, PIRP pIrp )
{
	NTSTATUS ntStatus;
	PTDI_FILTER_DEVICE_EXTENSION pDeviceExtension;
	PIO_STACK_LOCATION pIrpSp;
	PFILE_OBJECT pFileObject;
	TDI_REQUEST_KERNEL_RECEIVE *pTdiRecvParam;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	IO_STACK_LOCATION *pIrpSpNext;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	PTDI_REQUEST_KERNEL_SET_EVENT pTdiSetEvent;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList;
	PLIST_ENTRY pListEntry;
	BYTE MinorFunction;
	PEPROCESS pEProcess;
	PETHREAD pThread;
	CHAR bIsSend;
	BYTE OldIrql;
	hash_key key;

	//_try
	//{
		//DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon enter TdiFilterInternalIoControl\n" );
		//KdBreakPoint();

		if( FALSE == IsDriverDevice( pDeviceObject, pIrp ) )
		{
			ASSERT( FALSE );
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: IsDriverDevice return FALSE\n" );
			ntStatus = STATUS_INVALID_PARAMETER;
			goto COMPLETE_IRP;
		}

		pIrpSp = IoGetCurrentIrpStackLocation( pIrp );
		pFileObject = pIrpSp->FileObject;
		pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pDeviceObject->DeviceExtension;

		if( FALSE == g_bFiltering )
		{
			if( g_FilterDeviceForDeviceTcp == pDeviceObject || 
				g_FilterDeviceForDeviceUdp == pDeviceObject )
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: g_bFiltering == FALSE pDeviceObject == g_pFilterDevicexxx \n" );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}
		}

		if( g_DevTdiFilter == pDeviceObject )
		{
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: g_DevTdiFilter == pDeviceObject" );
			ntStatus = STATUS_SUCCESS;
			goto COMPLETE_IRP;
		}

		pThread = pIrp->Tail.Overlay.Thread;
		if( NULL == pThread )
		{
			pEProcess = IoGetCurrentProcess();
		}
		else
		{
			pEProcess = IoThreadToProcess( pThread );
		}

		DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: got the eprocess of the thread: 0x%0.8x \n", pEProcess );
		
		ASSERT( NULL != pEProcess );

		MinorFunction = pIrpSp->MinorFunction;

		if( TDI_SEND == MinorFunction || 
			TDI_SEND_DATAGRAM == MinorFunction )
		{
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, " TDI_SEND SystemBuffer is 0x%0.8x, MdlAddress Is 0x%0.8x, UserBuffer is 0x%0.8x \n", 
				pIrp->AssociatedIrp.SystemBuffer, 
				pIrp->MdlAddress, 
				pIrp->UserBuffer );
		}
		else
		{
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, " TDI_RECEIVE SystemBuffer is 0x%0.8x, MdlAddress Is 0x%0.8x, UserBuffer is 0x%0.8x \n", 
				pIrp->AssociatedIrp.SystemBuffer, 
				pIrp->MdlAddress, 
				pIrp->UserBuffer );
		}

		if( TDI_SEND == MinorFunction ||
			TDI_SEND_DATAGRAM == MinorFunction || 
			TDI_RECEIVE == MinorFunction || 
			TDI_RECEIVE_DATAGRAM == MinorFunction )
		{
			//KdBreakPoint();
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: MinorFunction == TDI_SENDXXX, TDI_RECEIVEXXX \n" );

			if( TDI_RECEIVE == MinorFunction && 
				TDI_RECEIVE_PEEK == ( ULONG )pIrpSp->Parameters.Others.Argument2 )
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: MinorFunction == TDI_RECEIVE recv flags == TDI_RECEIVE_PEEK \n" );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;

			pProcessNetWorkTrafficInfo = GetProcessNetWorkTrafficInfoFromEProcess( pEProcess );
			if( NULL == pProcessNetWorkTrafficInfo )
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: GetProcessNetWorkTrafficInfoFromEProcess return NULL \n" );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			if( FALSE != pProcessNetWorkTrafficInfo->bStopSend &&  
				( TDI_SEND == MinorFunction || 
				TDI_SEND_DATAGRAM == MinorFunction ) )
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: prohibit send! \n" );
				goto WHEN_ACCESS_DENIED;
			}

			if( FALSE != pProcessNetWorkTrafficInfo->bStopRecv && 
				( TDI_RECEIVE_DATAGRAM == MinorFunction || 
				TDI_RECEIVE == MinorFunction ) )
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: prohibit receive \n" );
				goto WHEN_ACCESS_DENIED;
			}

			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: check sendingspeed \n" );

			if( TRUE == InterlockedExchangeAdd( &g_bThreadsRunning, 0 ) && 
				( pProcessNetWorkTrafficInfo->SendingSpeed.LowPart != 0xFFFFFFFF && 
				pProcessNetWorkTrafficInfo->SendingSpeed.HighPart != 0x7FFFFFFF ) )
			{
				if( NULL == pIrp->AssociatedIrp.SystemBuffer && 
					( TDI_SEND == MinorFunction || 
					TDI_SEND_DATAGRAM == MinorFunction ) )
				{
					//KdBreakPoint();
 
					if( TRUE == IoIsOperationSynchronous( pIrp ) )
					{
						DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: IoIsOperationSynchronous return TRUE \n" );
						ntStatus = TdiFilterSyncSendProcess( pProcessNetWorkTrafficInfo, 
							pDeviceObject, 
							pIrp );

						ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );

						return ntStatus;
					}
					else
					{
						KIRQL IrpSpIrql;
						hash_key key;
						PDRIVER_CANCEL  OldCancelRoutine;

						DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: add irp to process irp list \n" );
						//ExInterlockedInsertTailList( &pProcessNetWorkTrafficInfo->IrpList, 
						//	&pIrp->Tail.Overlay.ListEntry, 
						//	&pProcessNetWorkTrafficInfo->IrpListLock );

						IoMarkIrpPending( pIrp );
						key.quad_part = make_hash_key( 0, ( DWORD )pIrp );

						KeAcquireSpinLock( &pProcessNetWorkTrafficInfo->IrpListLock, &IrpSpIrql ); 

						DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterInternalIoControl add_hash_item 0x%0.8x \n", pIrp );
						ntStatus = add_hash_item( &g_MasterIrpHash, key, ( hash_value )pProcessNetWorkTrafficInfo );
						DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterInternalIoControl add_hash_item return 0x%0.8x \n", ntStatus );
						//ASSERT( NT_SUCCESS( ntStatus ) );

						OldCancelRoutine = IoSetCancelRoutine( pIrp, TdiFilterCancel );
						ASSERT( NULL == OldCancelRoutine );

						InsertTailList( &pProcessNetWorkTrafficInfo->IrpList, &pIrp->Tail.Overlay.ListEntry );

						if( pIrp->Cancel )
						{
							OldCancelRoutine = IoSetCancelRoutine( pIrp, NULL);
							if( OldCancelRoutine )
							{
								RemoveEntryList( &pIrp->Tail.Overlay.ListEntry );
								KeReleaseSpinLock( &pProcessNetWorkTrafficInfo->IrpListLock, IrpSpIrql );
								pIrp->IoStatus.Status = STATUS_CANCELLED; 
								pIrp->IoStatus.Information = 0;
								IoCompleteRequest( pIrp, IO_NO_INCREMENT );
								return STATUS_PENDING;
							}
						}

						KeReleaseSpinLock( &pProcessNetWorkTrafficInfo->IrpListLock, IrpSpIrql );

						DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: ExInterlockedInsertTailList insert irp to pProcessNetWorkTrafficInfo->IrpList  \n" );
						ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );

						KeSetEvent( &g_EventIrpListAdded, 0, FALSE );
						return STATUS_PENDING;
					}
				}
			}

			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: wrap completion \n" );
			pCompletionWrap = ( PTDI_COMPLETION_WRAP )ExAllocateFromNPagedLookasideList( &g_CompletionWrapList );
			if( NULL == pCompletionWrap )
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: ExAllocateFromNPagedLookasideList return NULL \n" );
				ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			if( TDI_SEND == MinorFunction || 
				TDI_SEND_DATAGRAM == MinorFunction )
			{
				bIsSend = TRUE;
			}
			else
			{
				bIsSend = FALSE;
			}

			DebugPrintEx( IO_INTERNAL_CONTROL_INFO,  "netmon TdiFilterInternalIoControl: set the irp completion wrap \n" );
			pCompletionWrap->bSendOpera = bIsSend;
			pCompletionWrap->bWrap = FALSE;
			pCompletionWrap->bAssocIrp = FALSE;
			pCompletionWrap->bSync = TRUE;
			pCompletionWrap->pEProcess = pEProcess;
			pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;

			ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );

			if( pIrp->CurrentLocation <= 1 )
			{
				ASSERT( FALSE );
				ExFreeToNPagedLookasideList( &g_CompletionWrapList, pCompletionWrap );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			IoCopyCurrentIrpStackLocationToNext( pIrp );
			
			IoSetCompletionRoutine( pIrp, 
				TdiFilterCompletion, 
				pCompletionWrap, 
				TRUE, 
				TRUE, 
				TRUE
				);

			g_CompletionIrpCount ++;
			DebugPrintEx( IRP_COMPLETION_INFO, "netmon ThreadSendingSpeedControl  completion count++ %d\n", g_CompletionIrpCount );

			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: call driver with completion wraped irp \n" );
			goto CALL_PDO_DRIVER; //CALL_PDO_DRIVER_WAIT_COMPLETE;

		}
		//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		else if( TDI_SET_EVENT_HANDLER == MinorFunction )
		{
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: TDI_SET_EVENT_HANDLER == MinorFunction \n" );

			//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;

			pTdiSetEvent = ( PTDI_REQUEST_KERNEL_SET_EVENT )&pIrpSp->Parameters;

			if( TDI_EVENT_RECEIVE == pTdiSetEvent->EventType || 
				TDI_EVENT_RECEIVE_EXPEDITED == pTdiSetEvent->EventType || 
				TDI_EVENT_CHAINED_RECEIVE == pTdiSetEvent->EventType || 
				TDI_EVENT_CHAINED_RECEIVE_EXPEDITED == pTdiSetEvent->EventType ||
				TDI_EVENT_RECEIVE_DATAGRAM == pTdiSetEvent->EventType )
			{
				pTdiEventHandlerList = NULL;
				pProcessNetWorkTrafficInfo = NULL;
				//KdBreakPoint();

				//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;

				if( NULL == pTdiSetEvent->EventHandler )
				{
					DWORD EventType;
					DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: NULL == pTdiSetEvent->EventHandler \n" );

					EventType = pTdiSetEvent->EventType;

					IoSkipCurrentIrpStackLocation( pIrp );
					ntStatus = IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

					if( !NT_SUCCESS( ntStatus ) )
					{
						DebugPrintEx( IO_INTERNAL_CONTROL_INFO,  "netmon TdiFilterInternalIoControl: IoCallDriver return error \n" );
						return ntStatus;
					}

					UpdateEventHandlerWrap( NULL,
						NULL,
						NULL, 
						pFileObject, 
						EventType, 
						NULL, 
						NULL, 
						&pTdiEventHandlerList, 
						DEL_EVENT_WRAP );

					DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: delete event wraped handler \n" );

					return ntStatus;
				}

				pProcessNetWorkTrafficInfo = GetProcessNetWorkTrafficInfoFromEProcess( pEProcess );
				if( NULL == pProcessNetWorkTrafficInfo )
				{
					DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: GetProcessNetWorkTrafficInfoFromEProcess return NULL \n" );
					goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
				}

				UpdateEventHandlerWrap( pProcessNetWorkTrafficInfo,
					pEProcess,
					pDeviceExtension->pTdiDeviceObject, 
					pFileObject, 
					pTdiSetEvent->EventType, 
					pTdiSetEvent->EventHandler,
					pTdiSetEvent->EventContext, 
					&pTdiEventHandlerList, 
					GET_EVENT_WRAP );

				ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );

				if( NULL == pTdiEventHandlerList )
				{
					goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
				}

				if( TDI_EVENT_RECEIVE == pTdiSetEvent->EventType || 
					TDI_EVENT_RECEIVE_EXPEDITED == pTdiSetEvent->EventType )
				{
					pTdiSetEvent->EventHandler = TdiFilterRecvEventHandler;
				}
				else if( TDI_EVENT_CHAINED_RECEIVE == pTdiSetEvent->EventType ||
					TDI_EVENT_CHAINED_RECEIVE_EXPEDITED == pTdiSetEvent->EventType )
				{
					pTdiSetEvent->EventHandler = TdiFilterChainedRecvHandler;
				}
				else
				{
					pTdiSetEvent->EventHandler = TdiFilterRecvDatagramEventHandler;
				}

				ASSERT( NULL != pTdiEventHandlerList->pTdiEventHandlerWrap );
				pTdiSetEvent->EventContext = pTdiEventHandlerList->pTdiEventHandlerWrap;

				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: IoCallDriver with event wraped irp \n" );
				
				IoSkipCurrentIrpStackLocation( pIrp );
				ntStatus = IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

				if( !NT_SUCCESS( ntStatus ) )
				{
					DeleteEventWrap( pTdiEventHandlerList );
					DebugPrintEx( IO_INTERNAL_CONTROL_INFO,  "netmon TdiFilterInternalIoControl: IoCallDriver return error \n" );
				}

				return ntStatus;
			}
			else
			{
				DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: is other event handler call pdo drver \n" );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}
		}
		else
		{
			DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: is other minor function call pdo drver \n" );
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl got one exception: 0x%0.8x \n", GetExceptionCode() );
	//}

SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER:
	IoSkipCurrentIrpStackLocation( pIrp );

CALL_PDO_DRIVER:
	DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: call pdo drver \n" );
	return IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

//CALL_PDO_DRIVER_WAIT_COMPLETE:
//	DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl: call pdo drver current irql is %d \n", KeGetCurrentIrql() );
//	ntStatus = IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );
//	ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
//	KeWaitForSingleObject( &g_EventCompletion, Executive, KernelMode, FALSE, NULL );
//	return ntStatus;

COMPLETE_IRP:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest( pIrp, 0 );
	return ntStatus;

WHEN_ACCESS_DENIED:
	DebugPrintEx( IO_INTERNAL_CONTROL_INFO, "netmon TdiFilterInternalIoControl Access denied\n" );
	ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
	ntStatus = STATUS_ACCESS_DENIED;
	goto COMPLETE_IRP;
}

NTSTATUS TdiFilterIoControl( PDEVICE_OBJECT pDeviceObject, PIRP pIrp )
{
	NTSTATUS ntStatus;
	PTDI_FILTER_DEVICE_EXTENSION pDeviceExtension;
	PIO_STACK_LOCATION pIrpSp;
	DWORD dwOutputLength;

	pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pDeviceObject->DeviceExtension;
	pIrpSp = IoGetCurrentIrpStackLocation( pIrp );

	//_try 
	//{
		DebugPrintEx( IO_CONTROL_INFO, "netmon enter TdiFilterIoControl\n" );
		//KdBreakPoint();

		if( FALSE == IsDriverDevice( pDeviceObject, pIrp ) )
		{
			DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl FALSE == IsDriverDevice\n" );
			ntStatus = STATUS_INVALID_PARAMETER;
			goto COMPLETE_IRP;
		}

		if( FALSE == g_bFiltering && 
			( pDeviceObject == g_FilterDeviceForDeviceTcp || 
			pDeviceObject == g_FilterDeviceForDeviceUdp ) )
		{
			DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl FALSE == g_bFiltering\n" );

			goto SKIP_CURRENT_STACK_LOCATION_CALL_DRIVER;
		}

		if( g_DevTdiFilter != pDeviceObject )
		{
			if( PASSIVE_LEVEL == KeGetCurrentIrql() )
			{
				ntStatus = TdiMapUserRequest( pDeviceObject, 
					pIrp, 
					pIrpSp 
					);

				if( NT_SUCCESS( ntStatus ) )
				{
					DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl TdiMapUserRequest return success: 0x%0.8x minor function is 0x%0.8x\n", ntStatus, pIrpSp->MinorFunction );
					return TdiFilterInternalIoControl( pDeviceObject, pIrp );
				}

				//DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl TdiMapUserRequest return error: 0x%0.8x minor function is 0x%0.8x\n", ntStatus, pIrpSp->MinorFunction );
			}

			goto SKIP_CURRENT_STACK_LOCATION_CALL_DRIVER;
		}
		else
		{
			DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl g_DevTdiFilter == pDeviceObject\n" );
			DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == %d \n", pIrpSp->Parameters.DeviceIoControl.IoControlCode );


			if( IOCTL_TDI_GET_TDI_FILTER_DRIVER_VERSION == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DWORD *pId;
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_GET_TDI_FILTER_DRIVER_ID\n" );
				if( NULL == pIrp->AssociatedIrp.SystemBuffer || 
					sizeof( TDI_FILTER_DRIVER_VERSION ) > pIrpSp->Parameters.DeviceIoControl.OutputBufferLength )
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					dwOutputLength = 0;
					goto COMPLETE_IRP;
				}

				pId = ( DWORD* )pIrp->AssociatedIrp.SystemBuffer;

				RtlCopyMemory( pIrp->AssociatedIrp.SystemBuffer, TDI_FILTER_DRIVER_VERSION, sizeof( TDI_FILTER_DRIVER_VERSION ) );
				ntStatus = STATUS_SUCCESS;
				dwOutputLength = sizeof( TDI_FILTER_DRIVER_VERSION );
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_CHECK_FILTERING_STATE == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_CHECK_FILTERING_STATE \n" );
				if( NULL == pIrp->AssociatedIrp.SystemBuffer || 
					sizeof( BOOL ) > pIrpSp->Parameters.DeviceIoControl.OutputBufferLength )
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					dwOutputLength = 0;
					goto COMPLETE_IRP;
				}

				*( BOOL* )pIrp->AssociatedIrp.SystemBuffer = g_bFiltering;
				ntStatus = STATUS_SUCCESS;
				dwOutputLength = sizeof( BOOL );
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_GET_ALL_PROCESS_IO_INFO == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_GET_ALL_PROCESS_IO_INFO \n" );
				ntStatus = GetAllProcessesIoInformation( pIrp->AssociatedIrp.SystemBuffer, 
					pIrpSp->Parameters.DeviceIoControl.OutputBufferLength, 
					&dwOutputLength );

				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_OPEN_FILTERING == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_OPEN_FILTERING \n" );
				g_bFiltering = TRUE;
				ntStatus = STATUS_SUCCESS;
				dwOutputLength = 0;
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_CLOSE_FILTERING == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_CLOSE_FILTERING \n" );
				g_bFiltering = FALSE;
				ntStatus = STATUS_SUCCESS;
				dwOutputLength = 0;
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_GET_ALL_TRAFFIC == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				LARGE_INTEGER *pOutput;
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_GET_ALL_TRAFFIC \n" );
				if( NULL == pIrp->AssociatedIrp.SystemBuffer || 
					sizeof( LARGE_INTEGER ) * 2 > pIrpSp->Parameters.DeviceIoControl.OutputBufferLength )
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					dwOutputLength = 0;
					goto COMPLETE_IRP;
				}

				pOutput = ( LARGE_INTEGER* )pIrp->AssociatedIrp.SystemBuffer;
				pOutput[ 0 ].LowPart = g_AllRecvedDataSize.LowPart;
				pOutput[ 0 ].HighPart = g_AllRecvedDataSize.HighPart;
				pOutput[ 1 ].LowPart = g_AllSendedDataSize.LowPart;
				pOutput[ 1 ].HighPart = g_AllSendedDataSize.HighPart;

				ntStatus = STATUS_SUCCESS;
				dwOutputLength = sizeof( LARGE_INTEGER ) * 2;
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_START_UPDATE_PROCESS_IO_INFO == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_START_UPDATE_PROCESS_IO_INFO \n" );
				ntStatus = StartWorkThreadManageProcessInfo( ( PPROCESS_INFORMATION_RECORD )pIrp->AssociatedIrp.SystemBuffer, pIrpSp->Parameters.DeviceIoControl.InputBufferLength );
				dwOutputLength = 0;
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_GET_ALL_PROCESS_INFO == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_GET_ALL_PROCESS_INFO\n" );
				ntStatus = GetAllProcessesInformation( pIrp->AssociatedIrp.SystemBuffer, pIrpSp->Parameters.DeviceIoControl.OutputBufferLength, &dwOutputLength );
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_RELEASE_ALL_PROCESS_INFO == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_RELEASE_ALL_PROCESS_INFO\n" );
				ntStatus = ReleaseAllProcessesInformation();
				dwOutputLength = 0;
				goto COMPLETE_IRP;
			}
#ifdef _DEBUG
			else if( IOCTL_TDI_SET_DEBUG_TRACE_FLAG == pIrpSp->Parameters.DeviceIoControl.IoControlCode )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_SET_DEBUG_TRACE_FLAG \n" );
				if( NULL == pIrp->AssociatedIrp.SystemBuffer || 
					sizeof( DWORD ) > pIrpSp->Parameters.DeviceIoControl.InputBufferLength )
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					dwOutputLength = 0;
					goto COMPLETE_IRP;
				}
				
				dwPrintFlags = *( DWORD* )pIrp->AssociatedIrp.SystemBuffer;

				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl New debug flags is 0x%0.8x \n", dwPrintFlags );

				ntStatus = STATUS_SUCCESS;
				dwOutputLength = sizeof( DWORD );
				goto COMPLETE_IRP;
			}
			else if( IOCTL_TDI_SET_BP_FLAG )
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl IoControlCode == IOCTL_TDI_SET_DEBUG_TRACE_FLAG \n" );
				if( NULL == pIrp->AssociatedIrp.SystemBuffer || 
					sizeof( DWORD ) > pIrpSp->Parameters.DeviceIoControl.InputBufferLength )
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					dwOutputLength = 0;
					goto COMPLETE_IRP;
				}
				
				dwBPFlag = *( DWORD* )pIrp->AssociatedIrp.SystemBuffer;

				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl New bp flags is 0x%0.8x \n", dwBPFlag );

				ntStatus = STATUS_SUCCESS;
				dwOutputLength = sizeof( DWORD );
				goto COMPLETE_IRP;
			}
#endif
			else
			{
				DebugPrintEx( IO_CONTROL_INFO, "netmon TdiFilterIoControl receive other io control code, IoControlCode == 0x%0.8x \n" );
			}
		}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//	goto COMPLETE_IRP;
	//}

	ntStatus = STATUS_INVALID_PARAMETER;
	dwOutputLength = 0;

COMPLETE_IRP:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = dwOutputLength;
	IoCompleteRequest( pIrp, 0 );
	return ntStatus;

SKIP_CURRENT_STACK_LOCATION_CALL_DRIVER:
	IoSkipCurrentIrpStackLocation( pIrp );
	return IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );
}

NTSTATUS TdiFilterRecvEventHandler( IN PVOID  TdiEventContext,
									  IN CONNECTION_CONTEXT  ConnectionContext,
									  IN ULONG  ReceiveFlags,
									  IN ULONG  BytesIndicated,
									  IN ULONG  BytesAvailable,
									  OUT ULONG  *BytesTaken,
									  IN PVOID  Tsdu,
									  OUT PIRP  *IoRequestPacket
									  )
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION pIrpSp;
	PTDI_EVENT_HANDLER_WRAP pEventHandlerWrap;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	LARGE_INTEGER RecvedDataSize;

	ASSERT( NULL != TdiEventContext );

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon Enter TdiFilterRecvEventHandler \n" );

	pEventHandlerWrap = ( PTDI_EVENT_HANDLER_WRAP )TdiEventContext;

	ASSERT( NULL != pEventHandlerWrap && 
		NULL != pEventHandlerWrap->pOrgEventHandler );
	
	//KdBreakPoint();

	if( FALSE == MmIsAddressValid( pEventHandlerWrap ) )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvEventHandler pEventHandlerWrap is not valid reading address\n" );
		return STATUS_DATA_NOT_ACCEPTED;
	}

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvEventHandler event wrap 0x%0.8x, original event handler 0x%0.8x \n", 
		pEventHandlerWrap, 
		pEventHandlerWrap->pOrgEventHandler );
	//goto CALL_ORIGINAL_EVENT_HANDLER;

	if( FALSE == g_bFiltering )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvEventHandler g_bFiltering is false\n" );
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	pProcessNetWorkTrafficInfo = ReferenceProcessNetWorkTrafficInfo( pEventHandlerWrap->pEProcess );
	if( NULL == pProcessNetWorkTrafficInfo )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvEventHandler ReferenceProcessNetWorkTrafficInfo return NULL\n" );
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	if( FALSE != pProcessNetWorkTrafficInfo->bStopRecv )
	{
		ntStatus = STATUS_DATA_NOT_ACCEPTED;
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvEventHandler bStopRecv = TRUE\n" );

		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvEventHandler call org handler\n" );

	ntStatus = ( ( ClientEventReceive )pEventHandlerWrap->pOrgEventHandler )( 
		pEventHandlerWrap->pOrgEventContext, 
		ConnectionContext, 
		ReceiveFlags, 
		BytesIndicated, 
		BytesAvailable, 
		BytesTaken, 
		Tsdu, 
		IoRequestPacket 
		);

	if( NULL != BytesTaken && 
		0 != *BytesTaken )
	{
		RecvedDataSize.LowPart = *BytesTaken;
		RecvedDataSize.HighPart = 0;

		INTERLOCKED_COMPARE_EXCHANGE_ADD64( &pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize, RecvedDataSize );
		INTERLOCKED_HALF_COMPARE_EXCHANGE_ADD64( &g_AllRecvedDataSize, RecvedDataSize );
	}

	if( STATUS_MORE_PROCESSING_REQUIRED != ntStatus )
	{
		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	if( NULL == *IoRequestPacket )
	{
		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	pIrpSp = IoGetCurrentIrpStackLocation( *IoRequestPacket );

	pCompletionWrap = ( PTDI_COMPLETION_WRAP )ExAllocateFromNPagedLookasideList( &g_CompletionWrapList );

	if( NULL == pCompletionWrap )
	{
		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	pCompletionWrap->bSendOpera = FALSE;
	pCompletionWrap->bWrap = TRUE;
	pCompletionWrap->bAssocIrp = FALSE;
	pCompletionWrap->pCompletionRoutine = pIrpSp->CompletionRoutine;
	pCompletionWrap->pContext = pIrpSp->Context;
	pCompletionWrap->Control = pIrpSp->Control;
	pCompletionWrap->pEProcess = pEventHandlerWrap->pEProcess;
	pCompletionWrap->pProcessNetWorkTrafficInfo = pEventHandlerWrap->pProcessNetWorkTrafficInfo;

	pIrpSp->CompletionRoutine = TdiFilterCompletion;
	pIrpSp->Context = pCompletionWrap;
	pIrpSp->Control = SL_INVOKE_ON_CANCEL | 
		SL_INVOKE_ON_SUCCESS | 
		SL_INVOKE_ON_ERROR;

	g_CompletionIrpCount ++;
	DebugPrintEx( IRP_COMPLETION_INFO, "netmon TdiFilterRecvEventHandler  completion count++ %d\n", g_CompletionIrpCount );

	//Note: the recv event handler will add the BytesTaken number bytes to the record, and will add the next serial irp of this recv request recved bytes to record. by the ocmpletion wrap.

RELEASE_PROCESS_IO_INFO_RETURN:
	ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
	return ntStatus;

CALL_ORIGINAL_EVENT_HANDLER:
	return ( ( ClientEventReceive )pEventHandlerWrap->pOrgEventHandler )( 
		pEventHandlerWrap->pOrgEventContext, 
		ConnectionContext, 
		ReceiveFlags, 
		BytesIndicated, 
		BytesAvailable, 
		BytesTaken, 
		Tsdu, 
		IoRequestPacket
		);
}

NTSTATUS TdiFilterChainedRecvHandler(
    IN PVOID  TdiEventContext,
    IN CONNECTION_CONTEXT  ConnectionContext,
    IN ULONG  ReceiveFlags,
    IN ULONG  ReceiveLength,
    IN ULONG  StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID  TsduDescriptor
    )
{
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrap;
	NTSTATUS ntStatus;
	ClientEventChainedReceive pfChainedReceiveEventHandler;
	LPVOID pOriginalContext;
	LARGE_INTEGER RecvedDataSize;

	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfoHost;

	ASSERT( NULL != TdiEventContext );

	pTdiEventHandlerWrap = ( PTDI_EVENT_HANDLER_WRAP )TdiEventContext;

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon Enter TdiFilterChainedRecvHandler\n" );

	if( FALSE == MmIsAddressValid( pTdiEventHandlerWrap ) )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler MmIsAddressValid return FALSE\n" );
		return STATUS_DATA_NOT_ACCEPTED;
	}

	if( pTdiEventHandlerWrap->dwEventContextMark != TDI_EVENT_CONTEXT_MARK )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler Mark is not correct \n" );
		return STATUS_DATA_NOT_ACCEPTED;
	}

	ASSERT( NULL != pTdiEventHandlerWrap->pOrgEventHandler );
	ASSERT( NULL != pTdiEventHandlerWrap->pOrgEventContext );
	ASSERT( NULL != pTdiEventHandlerWrap->pEProcess );

	pfChainedReceiveEventHandler = ( ClientEventChainedReceive )pTdiEventHandlerWrap->pOrgEventHandler;
	pOriginalContext = pTdiEventHandlerWrap->pOrgEventContext;

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler original event handler 0x%0.8x \n", 
		pTdiEventHandlerWrap->pOrgEventHandler );

	if ( FALSE == g_bFiltering )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler FALSE == g_bFiltering\n" );
		goto CALL_ORG_EVENT_HANDLER;
	}

	pProcessNetWorkTrafficInfo = ReferenceProcessNetWorkTrafficInfo( pTdiEventHandlerWrap->pEProcess );
	if( NULL == pProcessNetWorkTrafficInfo )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler NULL == pProcessNetWorkTrafficInfo\n" );
		goto CALL_ORG_EVENT_HANDLER;
	}

	if( FALSE != pProcessNetWorkTrafficInfo->bStopRecv )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler FALSE != pProcessNetWorkTrafficInfo->bStopRecv\n" );
		ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
		return STATUS_DATA_NOT_ACCEPTED;
	}

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterChainedRecvHandler call pfChainedReceiveEventHandler\n" );

	ntStatus = pfChainedReceiveEventHandler( 
		pOriginalContext, 
		ConnectionContext, 
		ReceiveFlags, 
		ReceiveLength, 
		StartingOffset, 
		Tsdu,
		TsduDescriptor 
		);

	if( NT_SUCCESS( ntStatus ) )
	{
		RecvedDataSize.LowPart = ReceiveLength;
		RecvedDataSize.HighPart = 0;

		pProcessNetWorkTrafficInfoHost = pTdiEventHandlerWrap->pProcessNetWorkTrafficInfo;
		INTERLOCKED_COMPARE_EXCHANGE_ADD64( &pProcessNetWorkTrafficInfoHost->AllSuccRecvedDataSize, RecvedDataSize );
		INTERLOCKED_HALF_COMPARE_EXCHANGE_ADD64( &g_AllRecvedDataSize, RecvedDataSize );
	}

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon leave TdiFilterChainedRecvHandler\n" );

	ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
	return ntStatus;

CALL_ORG_EVENT_HANDLER:
	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon leave TdiFilterChainedRecvHandler direct call pfChainedReceiveEventHandler\n" );
	return pfChainedReceiveEventHandler( 
		pOriginalContext, 
		ConnectionContext, 
		ReceiveFlags, 
		ReceiveLength, 
		StartingOffset, 
		Tsdu,
		TsduDescriptor 
		);
}

NTSTATUS  TdiFilterRecvDatagramEventHandler(
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
    )
{
	NTSTATUS ntStatus;
	ClientEventReceiveDatagram pfOrgEventHandler;
	TDI_EVENT_HANDLER_WRAP *pEventHandlerWrap;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	LPVOID pOrgEventContext;
	LARGE_INTEGER RecvedDataSize;

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon Enter TdiFilterRecvDatagramEventHandler \n" );

	pEventHandlerWrap = ( PTDI_EVENT_HANDLER_WRAP )TdiEventContext;

	if( FALSE == MmIsAddressValid( pEventHandlerWrap ) )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler MmIsAddressValid return FALSE\n" );
		goto RETRUN_ERROR;
	}

	if( TDI_EVENT_CONTEXT_MARK != pEventHandlerWrap->dwEventContextMark )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler TDI_EVENT_CONTEXT_MARK error\n" );
		goto RETRUN_ERROR;
	}

	ASSERT( NULL != pEventHandlerWrap->pOrgEventHandler );

	pfOrgEventHandler = ( ClientEventReceiveDatagram )pEventHandlerWrap->pOrgEventHandler;
	pOrgEventContext = pEventHandlerWrap->pOrgEventContext;

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler original event handler 0x%0.8x \n", 
		pfOrgEventHandler );

	//goto CALL_ORIGINAL_EVENT_HANDLER;

	if( FALSE == g_bFiltering )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler g_bFiltering = FALSE\n" );
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	pProcessNetWorkTrafficInfo = ReferenceProcessNetWorkTrafficInfo( pEventHandlerWrap->pEProcess );
	if( NULL == pProcessNetWorkTrafficInfo )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler pProcessNetWorkTrafficInfo = NULL\n" );
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	if( FALSE != pProcessNetWorkTrafficInfo->bStopRecv )
	{
		DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler bStopRecv = TRUE\n" );
		ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
		return STATUS_DATA_NOT_ACCEPTED;
	}

	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler call pfOrgEventHandler\n" );
	ntStatus = pfOrgEventHandler( pOrgEventContext, 
		SourceAddressLength,
		SourceAddress,
		OptionsLength, 
		Options, 
		ReceiveDatagramFlags, 
		BytesIndicated, 
		BytesAvailable, 
		BytesTaken, 
		Tsdu, 
		IoRequestPacket
		);

	RecvedDataSize.LowPart = BytesAvailable;
	RecvedDataSize.HighPart = 0;

	INTERLOCKED_COMPARE_EXCHANGE_ADD64( 
		&pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize,
		RecvedDataSize );

	INTERLOCKED_HALF_COMPARE_EXCHANGE_ADD64( 
		&g_AllRecvedDataSize, 
		RecvedDataSize );
	ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon Leave TdiFilterRecvDatagramEventHandler \n" );
	return ntStatus;

CALL_ORIGINAL_EVENT_HANDLER:
	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon TdiFilterRecvDatagramEventHandler direct call pfOrgEventHandler\n" );
	return pfOrgEventHandler( pOrgEventContext, 
		SourceAddressLength,
		SourceAddress,
		OptionsLength, 
		Options, 
		ReceiveDatagramFlags, 
		BytesIndicated, 
		BytesAvailable, 
		BytesTaken, 
		Tsdu, 
		IoRequestPacket
		);
RETRUN_ERROR:
	DebugPrintEx( RECV_EVENT_HANDLER_INFO, "netmon Leave TdiFilterRecvDatagramEventHandler \n" );
	return STATUS_DATA_NOT_ACCEPTED;
}

NTSTATUS TdiFilterCompletion( PDEVICE_OBJECT pDeviceObject, PIRP pIrp, LPVOID pContext )
{
	NTSTATUS ntStatus;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfoHost;
	LARGE_INTEGER TransferredDataSize;
	PIRP pMasterIrp;
	PIO_STACK_LOCATION pIrpSp;

	g_CompletionIrpCount --;
	DebugPrintEx( IRP_COMPLETION_INFO, "netmon Enter TdiFilterCompletion  completion-- count %d\n", g_CompletionIrpCount );

	//ASSERT( NULL == pDeviceObject );

	if( FALSE == MmIsAddressValid( pContext ) )
	{
		ASSERT( FALSE );
		goto RETURN_SUCCESS;
	}

	if( NULL == pIrp || 
		NULL == pContext )
	{
		ASSERT( FALSE );
		goto RETURN_SUCCESS;
	}

	ntStatus = pIrp->IoStatus.Status;

	pCompletionWrap = ( PTDI_COMPLETION_WRAP )pContext;
	
	ASSERT( NULL != pCompletionWrap->pEProcess );

	DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion status == 0x%0.8x \n", pIrp->IoStatus.Status );

	if( NT_SUCCESS( ntStatus ) )
	{
		pProcessNetWorkTrafficInfo = ReferenceProcessNetWorkTrafficInfo( pCompletionWrap->pEProcess );
		if( NULL == pProcessNetWorkTrafficInfo )
		{
			DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion ReferenceProcessNetWorkTrafficInfo return NULL, complete this irp \n" );
			goto COMPLETE_IRP;
		} //Check the process of completion context validity.

		TransferredDataSize.LowPart = pIrp->IoStatus.Information;
		TransferredDataSize.HighPart = 0;

		pProcessNetWorkTrafficInfoHost = ( PPROCESS_NETWORK_TRAFFIC )pCompletionWrap->pProcessNetWorkTrafficInfo;

		ASSERT( NULL != pProcessNetWorkTrafficInfoHost );
		ASSERT( pProcessNetWorkTrafficInfoHost == pProcessNetWorkTrafficInfo );

		DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion ReferenceProcessNetWorkTrafficInfo, updating traffic record TransferredDataSize %u\n", 
			TransferredDataSize.LowPart );
		if( pCompletionWrap->bSendOpera )
		{
			INTERLOCKED_COMPARE_EXCHANGE_ADD64( &pProcessNetWorkTrafficInfoHost->AllSuccSendedDataSize, 
				TransferredDataSize );

			INTERLOCKED_COMPARE_EXCHANGE_ADD64( &g_AllSendedDataSize, 
				TransferredDataSize );
		}
		else
		{
			INTERLOCKED_COMPARE_EXCHANGE_ADD64( &pProcessNetWorkTrafficInfoHost->AllSuccRecvedDataSize, 
				TransferredDataSize );

			INTERLOCKED_COMPARE_EXCHANGE_ADD64( &g_AllRecvedDataSize, 
				TransferredDataSize );
		}

		ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
	}

COMPLETE_IRP:
	DebugPrintEx( IRP_COMPLETION_INFO, "netmon TdiFilterCompletion COMPLETE_IRP \n" );
	ASSERT( FALSE == ( pCompletionWrap->bWrap && pCompletionWrap->bAssocIrp ) );

	if( FALSE == pCompletionWrap->bWrap || 
		NULL == pCompletionWrap->pCompletionRoutine )
	{
		goto CHECK_PENDING_RETURN;
	}

	if( NT_SUCCESS( ntStatus ) )
	{
		if( SL_INVOKE_ON_SUCCESS & pCompletionWrap->Control )
		{
			goto CALL_ORG_COMPLETION_FUNCTION;
		}
	}
	else
	{
		if( SL_INVOKE_ON_ERROR & pCompletionWrap->Control )
		{
			goto CALL_ORG_COMPLETION_FUNCTION;
		}
	}

	if( TRUE == pIrp->Cancel )
	{
		if( SL_INVOKE_ON_CANCEL | pCompletionWrap->Control )
		{
			goto CALL_ORG_COMPLETION_FUNCTION;
		}
	}

	goto COMPLETE_ASSOCIATED_IRP;

CHECK_PENDING_RETURN:
	DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion CHECK_PENDING_RETURN \n" );
	if( FALSE == pIrp->PendingReturned )
	{
		goto COMPLETE_ASSOCIATED_IRP;
	}
	
	if( TRUE == pCompletionWrap->bAssocIrp ) //If this irp is the associated irp, it don't need to have the pending flag.
	{
		goto COMPLETE_ASSOCIATED_IRP;
	}

	if( TRUE == pCompletionWrap->bWrap ) //If have wraped completion routine, then left this pending flag seting operation to it.
	{
		goto COMPLETE_ASSOCIATED_IRP;
	}

	IoGetCurrentIrpStackLocation( pIrp )->Control |= SL_PENDING_RETURNED;

	goto COMPLETE_ASSOCIATED_IRP;

CALL_ORG_COMPLETION_FUNCTION:
	DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion CALL_ORG_COMPLETION_FUNCTION \n" );
	ntStatus = pCompletionWrap->pCompletionRoutine( pDeviceObject, 
		pIrp, 
		pCompletionWrap->pContext );

COMPLETE_ASSOCIATED_IRP:
	DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion COMPLETE_ASSOCIATED_IRP \n" );
	if( FALSE == pCompletionWrap->bAssocIrp )
	{
		goto FREE_COMPLETION_WRAP;
	}

	if( NULL == pIrp->AssociatedIrp.MasterIrp )
	{
		goto FREE_COMPLETION_WRAP;
	}

	pMasterIrp = pIrp->AssociatedIrp.MasterIrp;
	pMasterIrp->IoStatus.Information += pIrp->IoStatus.Information;
	pMasterIrp->IoStatus.Status = pIrp->IoStatus.Status;

	DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCompletion MasterIrp 0x%0.8x Associated irp count is 0x%0.8x\n", 
		pMasterIrp, 
		pMasterIrp->AssociatedIrp.IrpCount );
	if( 1 == pMasterIrp->AssociatedIrp.IrpCount )
	{
		INT32 nRet;
		hash_key key;

		key.quad_part = make_hash_key( 0, ( DWORD )pMasterIrp );

		IoSetCancelRoutine( pMasterIrp, NULL );

		DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCompletion del_hash_item 0x%0.8x \n", pMasterIrp );
		//KdBreakPoint();
		nRet = del_hash_item( &g_MasterIrpHash, key, NULL );
		DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCompletion del_hash_item 0x%0.8x return 0x%0.8x\n", pMasterIrp, nRet );
		//ASSERT( 0 <= nRet );
	}

	DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion master irp 0x%0.8x, master irp cancel routine 0x%0.8x, return length %d, status 0x%0.8x \n", 
		pMasterIrp, 
		pMasterIrp->CancelRoutine, 
		pIrp->IoStatus.Information, 
		pIrp->IoStatus.Status 
		);

FREE_COMPLETION_WRAP:
	DebugPrintEx( IRP_COMPLETION_INFO,  "netmon TdiFilterCompletion FREE_COMPLETION_WRAP\n" );
	ExFreeToNPagedLookasideList( &g_CompletionWrapList, pCompletionWrap );

	ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
	KeSetEvent( &g_EventCompletion, 0, FALSE );
	return ntStatus;

RETURN_SUCCESS:
	return STATUS_SUCCESS;
}

NTSTATUS TdiFilterSyncSendProcess( PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo, 
								 PDEVICE_OBJECT pDeviceObject, 
								 PIRP pIrp )
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION pIrpSp;
	PTDI_FILTER_DEVICE_EXTENSION pDeviceExtension;
	LARGE_INTEGER SendedSizeOneSec;
	LARGE_INTEGER SendRequireSize;
	PPROCESS_INFORMATION_RECORD pProcessInformation;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	PIO_STACK_LOCATION pIrpSpNext;
	PIRP pAssocIrp;
	PMDL pMdlAlloced;
	PMDL pMdl;
	PBYTE pMdlVA;
	DWORD dwSendLength;
	DWORD dwSendedLength;

	//KdBreakPoint();
	DebugPrintEx( SYNC_SEND_IRP_PROCESS_INFO, "netmon enter TdiFilterSyncSendProcess\n" );

	ASSERT( NULL == pIrp->AssociatedIrp.SystemBuffer );

	//_try
	//{
		pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pDeviceObject->DeviceExtension;
		pIrpSp = IoGetCurrentIrpStackLocation( pIrp );

		//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;

		ASSERT( TDI_SEND == pIrpSp->MinorFunction || 
			TDI_SEND_DATAGRAM == pIrpSp->MinorFunction );

		dwSendLength = ( DWORD )pIrpSp->Parameters.Others.Argument1;

		if( pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart >= dwSendLength )
		{
			if( pIrp->CurrentLocation <= 1 )
			{
				ASSERT( FALSE );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			for( ; ; )
			{
				SendedSizeOneSec.QuadPart = pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart;
				SendedSizeOneSec.QuadPart += dwSendLength;

				if( SendedSizeOneSec.QuadPart > 
					pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart )
				{
					if( pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart >= dwSendLength )
					{
						KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
						continue;
					}
					else
					{
						break;
					}
				}
				else
				{
					break;
				}
			}

			pCompletionWrap = ( PTDI_COMPLETION_WRAP )ExAllocateFromNPagedLookasideList( &g_CompletionWrapList );
			if( NULL == pCompletionWrap )
			{
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart += dwSendLength;
			pCompletionWrap->bSendOpera = TRUE;
			pCompletionWrap->bWrap = FALSE;
			pCompletionWrap->bAssocIrp = FALSE;
			pCompletionWrap->bSync = TRUE;

			pCompletionWrap->pEProcess = pProcessNetWorkTrafficInfo->pEProcess;
			pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo; //must got the process inforamtion reference.

			IoCopyCurrentIrpStackLocationToNext( pIrp );

			IoSetCompletionRoutine( pIrp, 
				TdiFilterCompletion, 
				pCompletionWrap, 
				TRUE, 
				TRUE, 
				TRUE
				);

			g_CompletionIrpCount ++;
			DebugPrintEx( IRP_COMPLETION_INFO, "netmon TdiFilterSyncSendProcess  completion count++ %d\n", g_CompletionIrpCount );
			ntStatus = IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

			return ntStatus;
		}
		else
		{
			dwSendedLength = 0;
			pMdl = pIrp->MdlAddress;

			if( NULL == pMdl )
			{
				ASSERT( FALSE );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			if( dwSendLength != MmGetMdlByteCount( pMdl ) )
			{
				ASSERT( FALSE );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			pMdlVA = MmGetMdlVirtualAddress( pMdl );

			if( NULL == pMdlVA )
			{
				ASSERT( pMdlVA );
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			ntStatus = STATUS_UNSUCCESSFUL;

			for( ; ; )
			{
				if( dwSendedLength >= dwSendLength )
				{
					return ntStatus;
				}

				SendRequireSize.QuadPart = dwSendLength - dwSendedLength;

				if( pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart < SendRequireSize.QuadPart )
				{
					SendRequireSize.QuadPart = pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart;
				}

				pAssocIrp = IoMakeAssociatedIrp( pIrp, pDeviceExtension->pTdiDeviceObject->StackSize );
				if( NULL == pAssocIrp )
				{
					goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
				}

				pMdlAlloced = IoAllocateMdl( 
					pMdlVA, 
					dwSendLength, 
					FALSE, 
					0, 
					pAssocIrp 
					);

				if( NULL == pMdlAlloced )
				{
					IoFreeIrp( pAssocIrp );
					goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
				}

				InterlockedExchangeAdd( &pIrp->AssociatedIrp.IrpCount, 1 );

				IoBuildPartialMdl( pIrp->MdlAddress, 
					pMdlAlloced,  
					pMdlVA + dwSendedLength, 
					SendRequireSize.LowPart );

				dwSendedLength += SendRequireSize.LowPart;

				pIrpSpNext = IoGetNextIrpStackLocation( pAssocIrp );

				pIrpSpNext->MajorFunction = pIrpSp->MajorFunction;
				pIrpSpNext->MinorFunction = pIrpSp->MinorFunction;
				pIrpSpNext->DeviceObject = pDeviceExtension->pTdiDeviceObject;
				pIrpSpNext->FileObject = pIrpSp->FileObject;

				pIrpSpNext->Parameters.Others.Argument1 = ( PVOID )SendRequireSize.LowPart;
				pIrpSpNext->Parameters.Others.Argument2 = pIrpSp->Parameters.Others.Argument2;

				pAssocIrp->MdlAddress = pMdlAlloced;

				for( ; ; )
				{
					if( pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart + SendRequireSize.QuadPart >
						pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart )
					{
						if( SendRequireSize.QuadPart <= pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart )
						{
							KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
							continue;
						}
						else
						{
							break;
						}
					}
					else
					{
						break;
					}
				}

				pCompletionWrap = ( PTDI_COMPLETION_WRAP )ExAllocateFromNPagedLookasideList( &g_CompletionWrapList );
				if( NULL == pCompletionWrap )
				{
					goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
				}

				pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart += SendRequireSize.LowPart;
				pCompletionWrap->bSendOpera = TRUE;
				pCompletionWrap->bWrap = FALSE; //If synchronized operation, it must not have the completion routine.
				pCompletionWrap->bAssocIrp = FALSE;
				pCompletionWrap->bSync = TRUE;

				pCompletionWrap->pEProcess = pProcessNetWorkTrafficInfo->pEProcess;
				pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;

				IoSetCompletionRoutine( pAssocIrp, 
					TdiFilterCompletion, 
					pCompletionWrap, 
					TRUE, 
					TRUE, 
					TRUE 
					);

				g_CompletionIrpCount ++;
				DebugPrintEx( IRP_COMPLETION_INFO, "netmon TdiFilterSyncSendProcess completion count++ %d\n", g_CompletionIrpCount );
				ntStatus = IoCallDriver( pIrpSpNext->DeviceObject, pAssocIrp );
				ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );			}
		}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//}

SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER:
	IoSkipCurrentIrpStackLocation( pIrp );
//CALL_PDO_DRIVER:
	return IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );
}

VOID ThreadWaitCompletion( PVOID pParam )
{
	for( ; ; )
	{
		KeWaitForSingleObject( &g_EventCompletion, Executive, KernelMode, FALSE, NULL );
		
		if( 0 == InterlockedExchangeAdd( &g_CompletionIrpCount, 0 ) )
		{
			break;
		}
	}
}

VOID ThreadSendingSpeedControl( PVOID pParam )
{
	NTSTATUS ntStatus;
	BYTE OldIrql;
	BOOL bWaitEvent;
	DWORD dwConfiguredProcessIoInfoCount;
	LIST_ENTRY AllProcessIoList;
	LIST_ENTRY *pListEntry;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	PIRP pIrp;
	PIRP pIrpListed;
	PLIST_ENTRY pIrpListEntry;
	DWORD dwIrpCount;
	PIO_STACK_LOCATION pIrpSp;
	PIO_STACK_LOCATION pIrpSpNext;
	PTDI_REQUEST_KERNEL_SEND pTdiSendParam;
	PTDI_REQUEST_KERNEL_SENDDG pTdiSendDGParam;
	PTDI_FILTER_DEVICE_EXTENSION pDeviceExtension;
	DWORD dwTransferLength;
	DWORD dwThreadWaitTime;
	LARGE_INTEGER TransferredSize;
	BOOL bIrpContextNotAlloced;
	DWORD dwTransferred;
	PMDL pMdl;
	PMDL pAllocMdl;
	PMDL pMdlNext;
	PBYTE pIrpMdlVA;
	BOOL bAssocIrpMakeDone;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	DWORD dwIrpQueryLength;
	PIRP pAssocIrp;
	PIO_STACK_LOCATION pAssocIrpSp;
	PIO_STACK_LOCATION pAssocIrpSpNext;
	DWORD dwSendingSpeedHigh;
	hash_key key;
	INT32 nRet;

	bWaitEvent = TRUE;
	dwConfiguredProcessIoInfoCount = 0;

	DebugPrintEx( SEND_SPEED_CONTROL_INFO,  "netmon Enter ThreadSendingSpeedControl\n" );

	//_try
	//{
		for( ; ; )
		{
			//KdBreakPoint();

			if( TRUE == g_bThreadIrpProcessStop )
			{
				InitializeListHead( &AllProcessIoList );
				KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );
				
				pListEntry = g_ProcessIoInfoList.Flink;
				
				for( ; ; )
				{
					if( pListEntry == &g_ProcessIoInfoList )
					{
						break;
					}

					pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;

					InterlockedExchangeAdd( 
						&pProcessNetWorkTrafficInfo->dwRefCount, 
						1 );

					InsertTailList( &AllProcessIoList, &pProcessNetWorkTrafficInfo->ListEntry );

					pListEntry = pListEntry->Flink;
				}

				KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl KeReleaseSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );

				if( IsListEmpty( &AllProcessIoList ) )
				{
					break;
				}

				for( ; ; )
				{
					pListEntry = AllProcessIoList.Flink;

					if( pListEntry == &AllProcessIoList )
					{
						break;
					}

					RemoveEntryList( pListEntry );

					pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )CONTAINING_RECORD( pListEntry, PROCESS_NETWORK_TRAFFIC, ListEntry );

					pIrp = DequeueIrp( &pProcessNetWorkTrafficInfo->IrpList, &pProcessNetWorkTrafficInfo->IrpListLock );

					if( NULL == pIrp ) //If value is null, then reach the tail of the irp list.
					{
						continue;
					}

					//pIrp = ( PIRP )CONTAINING_RECORD( pIrpListEntry, IRP, Tail.Overlay.ListEntry );

					pIrpSp = IoGetCurrentIrpStackLocation( pIrp );
					pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pIrpSp->DeviceObject->DeviceExtension;

					DebugPrintEx( SEND_SPEED_CONTROL_INFO, " ThreadSendingSpeedControl minor function is %d \n", pIrpSp->MinorFunction );

					if( NULL == pIrp->AssociatedIrp.MasterIrp )
					{
						IoSetCancelRoutine( pIrp, NULL );

						key.quad_part = make_hash_key( 0, ( DWORD )pIrp );
						DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCompletion del_hash_item 0x%0.8x \n", pIrp );
						//KdBreakPoint();
						nRet = del_hash_item( &g_MasterIrpHash, key, NULL );
						DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterCompletion del_hash_item 0x%0.8x return 0x%0.8x\n", pIrp, nRet );
					}
					IoSkipCurrentIrpStackLocation( pIrp );
					IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );
					ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
				}

				break;
			}

			if( TRUE == bWaitEvent )
			{
				DebugPrintEx( SEND_SPEED_CONTROL_INFO,  "netmon ThreadSendingSpeedControl wait new irp\n" );
				ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
				KeWaitForSingleObject( &g_EventIrpListAdded, Executive, KernelMode, FALSE, &g_WaitNewIistItemTime );
			}

			if( 0 == dwConfiguredProcessIoInfoCount )
			{
				KeDelayExecutionThread( KernelMode, FALSE, &g_ThreadWaitConfigProcTime );
			}

			bWaitEvent = TRUE;
			dwConfiguredProcessIoInfoCount = 0;

			InitializeListHead( &AllProcessIoList );

			DebugPrintEx( SEND_SPEED_CONTROL_INFO,  "netmon ThreadSendingSpeedControl KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
			KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );

			pListEntry = g_ProcessIoInfoList.Flink;

			for( ; ; )
			{
				if( pListEntry == &g_ProcessIoInfoList )
				{
					break;
				}

				pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;
				if( pProcessNetWorkTrafficInfo->SendingSpeed.LowPart != 0xFFFFFFFF || 
					pProcessNetWorkTrafficInfo->SendingSpeed.HighPart != 0x7FFFFFFF )
				{
					dwConfiguredProcessIoInfoCount ++; //Record the count of the send speed configured process.
				}

				InterlockedExchangeAdd( 
					&pProcessNetWorkTrafficInfo->dwRefCount, 
					1 );

				InsertTailList( &AllProcessIoList, &pProcessNetWorkTrafficInfo->ListEntry );

				pListEntry = pListEntry->Flink;
			}

			KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
			DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl KeReleaseSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );

			if( IsListEmpty( &AllProcessIoList ) )
			{
				continue;
			}

			//KdBreakPoint();

			for( ; ; )
			{
				PDEVICE_OBJECT pPdoDevice;
				pListEntry = AllProcessIoList.Flink;

				ASSERT( TRUE == MmIsAddressValid( pListEntry ) );
				if( pListEntry == &AllProcessIoList )
				{
					break;
				}

				RemoveEntryList( pListEntry );

				pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )CONTAINING_RECORD( pListEntry, PROCESS_NETWORK_TRAFFIC, ListEntry );

				pIrp = DequeueIrp( &pProcessNetWorkTrafficInfo->IrpList, &pProcessNetWorkTrafficInfo->IrpListLock );

				if( NULL == pIrp ) //If value is null, then reach the tail of the irp list.
				{
					DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl process: %d irp list is empty. \n", pProcessNetWorkTrafficInfo->dwProcessId );
					goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
				}

				//pIrp = ( PIRP )CONTAINING_RECORD( pIrpListEntry, IRP, Tail.Overlay.ListEntry );

//#define METHOD_BUFFERED                 0
//#define METHOD_IN_DIRECT                1
//#define METHOD_OUT_DIRECT               2
//#define METHOD_NEITHER                  3

//#define TDI_SEND                 (0x07) METHOD_NEITHER
//#define TDI_RECEIVE              (0x08) METHOD_BUFFERED
//#define TDI_SEND_DATAGRAM        (0x09) METHOD_IN_DIRECT
//#define TDI_RECEIVE_DATAGRAM     (0x0A) METHOD_OUT_DIRECT
//#define TDI_SET_EVENT_HANDLER    (0x0B) METHOD_NEITHER

				bWaitEvent = FALSE;
				dwIrpCount = pIrp->AssociatedIrp.IrpCount;

				KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
				KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
				KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
				KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
				KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
				//pIrpSp = IoGetCurrentIrpStackLocation( pIrp );
				//pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pIrpSp->DeviceObject->DeviceExtension;

				//goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;

				if( 0 == dwIrpCount )
				{
					pIrpSp = IoGetCurrentIrpStackLocation( pIrp );
					pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pIrpSp->DeviceObject->DeviceExtension;
					pPdoDevice = pDeviceExtension->pTdiDeviceObject;
				}
				else
				{
					pIrpSp = IoGetNextIrpStackLocation( pIrp );
					pPdoDevice = pIrpSp->DeviceObject;
					pDeviceExtension = NULL;
				}

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl irp count is %d\n, pdo device is 0x%0.8x\n, Marjor func 0x%0.8x\n, Minor func 0x%0.8x\n, param1 0x%0.8x, param2 0x%0.8x \n", 
					dwIrpCount, 
					pPdoDevice, 
					pIrpSp->MajorFunction, 
					pIrpSp->MinorFunction, 
					pIrpSp->Parameters.Others.Argument1, 
					pIrpSp->Parameters.Others.Argument2 
					);

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "ThreadSendingSpeedControl minor function is %d \n", pIrpSp->MinorFunction );

				ASSERT( TDI_SEND == pIrpSp->MinorFunction || 
					TDI_SEND_DATAGRAM == pIrpSp->MinorFunction );

				if( TDI_SEND == pIrpSp->MinorFunction )
				{
					pTdiSendParam = ( PTDI_REQUEST_KERNEL_SEND )&pIrpSp->Parameters;
					dwTransferLength = pTdiSendParam->SendLength;		
				}
				else
				{
					pTdiSendDGParam = ( PTDI_REQUEST_KERNEL_SENDDG )&pIrpSp->Parameters;
					dwTransferLength = pTdiSendDGParam->SendLength;
				}

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "pIrp->AssociatedIrp.SystemBuffer = 0x%0.8x, MinorFunction = %d \n", pIrp->AssociatedIrp.SystemBuffer, IoGetCurrentIrpStackLocation( pIrp )->MinorFunction );
				
				//Control speeding speed by depart sending length and make these to associated irps, so this original irp become the master irp.
				if( dwTransferLength > pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart )
				{
					DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl process: %d packet send length %d is greater than send speed limit %d \n", 
						pProcessNetWorkTrafficInfo->dwProcessId, 
						dwTransferLength, 
						pProcessNetWorkTrafficInfo->SendingSpeed.LowPart );

					if( 0 == dwIrpCount )
					{
						DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl irp is master irp \n" );

						pMdl = pIrp->MdlAddress;
						if( NULL == pMdl )
						{
							ASSERT( FALSE );
							goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
						}

						if( dwTransferLength != MmGetMdlByteCount( pMdl ) )
						{
							ASSERT( FALSE );
							goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
						}
 
						pIrpMdlVA = MmGetMdlVirtualAddress( pMdl );;
						if( NULL == pIrpMdlVA )
						{
							ASSERT( FALSE );
							goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
						}

						dwTransferred = 0;

						for( ; ; )
						{
							if( dwTransferred >= dwTransferLength )
							{
								DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl irp is departing done\n" );
								goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
							}

							bAssocIrpMakeDone = FALSE;
							dwIrpQueryLength = dwTransferLength - dwTransferred;

							if( pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart < dwIrpQueryLength )
							{
								//If sending speed is negative, then it limits the max data size of you departed fragment of the packet.
								dwIrpQueryLength = pProcessNetWorkTrafficInfo->SendingSpeed.LowPart;
								DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl associated irp send length is %d \n", dwIrpQueryLength );
								dwSendingSpeedHigh = pProcessNetWorkTrafficInfo->SendingSpeed.HighPart;
							}
							else
							{
								DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl associated irp send length is %d, reach tail \n", dwIrpQueryLength );
								dwSendingSpeedHigh = 0;
							}

							ASSERT( NULL != pDeviceExtension );

							pAssocIrp = IoMakeAssociatedIrp( 
								pIrp, 
								pDeviceExtension->pTdiDeviceObject->StackSize 
								);

							if( NULL == pAssocIrp )
							{
								goto RELEASE_ASSOCIATED_IRP;
							}

							ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
							DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl allocated associated irp 0x%0.8x\n", 
								pAssocIrp );

							pAllocMdl = IoAllocateMdl( 
								pIrpMdlVA, 
								dwTransferLength, 
								FALSE, 
								0, 
								pAssocIrp 
								);

							if( NULL == pAllocMdl )
							{
								IoFreeIrp( pAssocIrp );
								goto RELEASE_ASSOCIATED_IRP;
							}

							DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl allocated mdl 0x%0.8x\n", 
								pAllocMdl );
							
							ASSERT( dwIrpQueryLength + dwTransferred <= dwTransferLength );

							IoBuildPartialMdl( 
								pIrp->MdlAddress, 
								pAllocMdl, 
								pIrpMdlVA - dwIrpQueryLength - dwTransferred + dwTransferLength, 
								dwIrpQueryLength 
								);

							DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl partial mdl builded addr 0x%0.8x, length %d\n", 
								pIrpMdlVA - dwIrpQueryLength - dwTransferred + dwTransferLength, 
								dwIrpQueryLength );

							dwTransferred += dwIrpQueryLength;

							ASSERT( pAssocIrp->AssociatedIrp.MasterIrp == pIrp );

							pAssocIrpSpNext = IoGetNextIrpStackLocation( pAssocIrp );

							//This new associated irp do the same function of the original irp.
							pAssocIrpSpNext->MajorFunction = pIrpSp->MajorFunction;
							pAssocIrpSpNext->MinorFunction = pIrpSp->MinorFunction;
							pAssocIrpSpNext->DeviceObject = pDeviceExtension->pTdiDeviceObject;
							pAssocIrpSpNext->FileObject = pIrpSp->FileObject;

							DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl set associating irp stack \n, Major func: %d\n Minor func: %d\n Device: 0x%0.8x\n, File object: 0x%0.8x \n", 
								pAssocIrpSpNext->MajorFunction, 
								pAssocIrpSpNext->MinorFunction, 
								pAssocIrpSpNext->DeviceObject, 
								pAssocIrpSpNext->FileObject 
								);

							if( TDI_SEND == pAssocIrpSpNext->MinorFunction )
							{
								PTDI_REQUEST_KERNEL_SEND pRequestSend;
								pRequestSend = ( PTDI_REQUEST_KERNEL_SEND )&pAssocIrpSpNext->Parameters;

								pRequestSend->SendFlags = pTdiSendParam->SendFlags;
								pRequestSend->SendLength = dwIrpQueryLength;

								DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl set associating irp stack \n, send flag 0x%0.8x, send length %d \n", 
									pRequestSend->SendFlags, 
									pRequestSend->SendLength 
									);
							}
							else
							{
								PTDI_REQUEST_KERNEL_SENDDG pRequestSendDG;
								pRequestSendDG = ( PTDI_REQUEST_KERNEL_SENDDG )&pAssocIrpSpNext->Parameters;

								pRequestSendDG->SendDatagramInformation = pTdiSendDGParam->SendDatagramInformation;;
								pRequestSendDG->SendLength = dwIrpQueryLength;
								DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl set associating irp stack \n, send datagram info 0x%0.8x, send length %d \n", 
									pRequestSendDG->SendDatagramInformation, 
									pRequestSendDG->SendLength 
									);
							}

							pAssocIrp->MdlAddress = pAllocMdl;
							bAssocIrpMakeDone = TRUE;

							DebugPrintEx( IRP_CANCEL_INFO, "netmon ThreadSendingSpeedControl MasterIrp 0x%0.8x Associated irp count is 0x%0.8x\n", 
								pIrp, 
								pIrp->AssociatedIrp.IrpCount );
							InterlockedExchangeAdd( &pIrp->AssociatedIrp.IrpCount, 1 );

							{	
								KIRQL IrpSpIrql;
								hash_key key;
								PDRIVER_CANCEL OldCancelRoutine;

								KeAcquireSpinLock( &pProcessNetWorkTrafficInfo->IrpListLock, &IrpSpIrql );
								key.quad_part = make_hash_key( 0, ( DWORD )pAssocIrp );

								DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterInternalIoControl add_hash_item 0x%0.8x \n", pIrp );
								ntStatus = add_hash_item( &g_MasterIrpHash, key, ( hash_value )pProcessNetWorkTrafficInfo );
								DebugPrintEx( IRP_CANCEL_INFO, "netmon TdiFilterInternalIoControl add_hash_item return 0x%0.8x \n", ntStatus );
								//ASSERT( NT_SUCCESS( ntStatus ) );

								IoMarkIrpPending( pAssocIrp );
								OldCancelRoutine = IoSetCancelRoutine( pAssocIrp, TdiFilterCancel );
								ASSERT( NULL == OldCancelRoutine );

								InsertTailList( &pProcessNetWorkTrafficInfo->IrpList, &pAssocIrp->Tail.Overlay.ListEntry );

								if( pIrp->Cancel )
								{
									OldCancelRoutine = IoSetCancelRoutine( pAssocIrp, NULL);
									if( OldCancelRoutine )
									{
										RemoveEntryList( &pIrp->Tail.Overlay.ListEntry );
										KeReleaseSpinLock( &pProcessNetWorkTrafficInfo->IrpListLock, IrpSpIrql );
										pAssocIrp->IoStatus.Status = STATUS_CANCELLED; 
										pAssocIrp->IoStatus.Information = 0;
										IoCompleteRequest( pAssocIrp, IO_NO_INCREMENT );
										continue;
									}
								}

								KeReleaseSpinLock( &pProcessNetWorkTrafficInfo->IrpListLock, IrpSpIrql );
							}
							//ExInterlockedInsertHeadList( &pProcessNetWorkTrafficInfo->IrpList, &pAssocIrp->Tail.Overlay.ListEntry, &pProcessNetWorkTrafficInfo->IrpListLock );

//#define TDI_ASSOCIATE_ADDRESS    (0x01)
//#define TDI_DISASSOCIATE_ADDRESS (0x02)
//#define TDI_CONNECT              (0x03)
//#define TDI_LISTEN               (0x04)
//#define TDI_ACCEPT               (0x05)
//#define TDI_DISCONNECT           (0x06)
//#define TDI_SEND                 (0x07)
//#define TDI_RECEIVE              (0x08)
//#define TDI_SEND_DATAGRAM        (0x09)
//#define TDI_RECEIVE_DATAGRAM     (0x0A)
//#define TDI_SET_EVENT_HANDLER    (0x0B)
//#define TDI_QUERY_INFORMATION    (0x0C)
//#define TDI_SET_INFORMATION      (0x0D)
//#define TDI_ACTION               (0x0E)
//
//#define TDI_DIRECT_SEND          (0x27)
//#define TDI_DIRECT_SEND_DATAGRAM (0x29)
							//delay this irp and its associated irps processing to next loop. 
							DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl associated irp inserted to process irp list \n" );

RELEASE_ASSOCIATED_IRP:
							if( FALSE == bAssocIrpMakeDone )
							{
								//Release previous added associated irps.
								for( ; ; )
								{
									DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl free associated irp %d \n", 
										pIrp->AssociatedIrp.IrpCount );

									if( 0 == pIrp->AssociatedIrp.IrpCount )
									{
										break;
									}

									pIrpListEntry = ExInterlockedRemoveHeadList( &pProcessNetWorkTrafficInfo->IrpList, 
										&pProcessNetWorkTrafficInfo->IrpListLock );


									DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl geted associated irp addr 0x%0.8x \n", 
										pIrpListEntry );

									if( NULL == pIrpListEntry )
									{
										ASSERT( FALSE );
										InterlockedExchangeAdd( &pIrp->AssociatedIrp.IrpCount, -1 );
										continue;
									}

									pIrpListed = CONTAINING_RECORD( pIrpListEntry, IRP, Tail.Overlay.ListEntry );
									pMdl = pIrpListed->MdlAddress;

									DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl geted mdl of associated irp 0x%0.8x \n", 
										pMdl );

									for( ; ; )
									{
										if( NULL == pMdl )
										{
											break;
										}

										pMdlNext = pMdl->Next;

										IoFreeMdl( pMdl );
										pMdl = pMdlNext;

										DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl geted next mdl of associated irp 0x%0.8x \n", 
											pMdl );
									}

									DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl free associated irp 0x%0.8x \n", 
										pIrpListed );
									IoFreeIrp( pIrpListed );
									InterlockedExchangeAdd( &pIrp->AssociatedIrp.IrpCount, -1 );
								}

								goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
							}

							continue;
						}
					}
				}

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl packet length lower than speed limit, or packet is associated irp \n" );

				dwThreadWaitTime = 0;

				//If sending speed is positive, then it limits the data size of one send time
				for( ; ; )
				{
					if( pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart + dwTransferLength > pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart )
					{
						//Delay the sending function to longer time to match the seted sending speed.
						if( dwTransferLength <= pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart )
						{
							KeDelayExecutionThread( KernelMode, FALSE, &g_SendingDelayTime );
							dwThreadWaitTime ++;
							if( 5 > dwThreadWaitTime )
							{
								DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl one second send length is over than speed length wait 10 milli-senconds \n" );

								continue;
							}

							ExInterlockedInsertHeadList( &pProcessNetWorkTrafficInfo->IrpList, 
								&pIrp->Tail.Overlay.ListEntry, 
								&pProcessNetWorkTrafficInfo->IrpListLock );

							DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl waited 50 milli-seconds \n" );
							goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
						}
						else
						{
							break;
						}
					}
					else
					{
						break;
					}
				}

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl send speed is correct\n" );

				bIrpContextNotAlloced = FALSE;
				pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart += dwTransferLength;
				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl new send length one second is %d\n", 
					pProcessNetWorkTrafficInfo->SendedSizeOneSec.LowPart );

				ASSERT( pIrpSp->MinorFunction == TDI_SEND || 
					pIrpSp->MinorFunction == TDI_SEND_DATAGRAM );

				if( 0 != dwIrpCount )
				{
					DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl irp is associated, master irp is 0x%0.8x \n", 
						pIrp->AssociatedIrp.MasterIrp );

					pCompletionWrap = ( PTDI_COMPLETION_WRAP )ExAllocateFromNPagedLookasideList( &g_CompletionWrapList );
					if( NULL != pCompletionWrap )
					{
						pCompletionWrap->bSendOpera = TRUE;
						pCompletionWrap->bWrap = FALSE;
						pCompletionWrap->bAssocIrp = TRUE;
						pCompletionWrap->pEProcess = pProcessNetWorkTrafficInfo->pEProcess;
						pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;
					}
					else
					{
						bIrpContextNotAlloced = TRUE;
					}

					pIrpSp = IoGetNextIrpStackLocation( pIrp );
					ASSERT( NULL != pIrpSp->DeviceObject );

					if( FALSE == bIrpContextNotAlloced )
					{
						IoSetCompletionRoutine( pIrp, 
							TdiFilterCompletion, 
							pCompletionWrap, 
							TRUE, 
							TRUE, 
							TRUE
							);

						DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl allocate completion wrap, call pdo 0x%0.8x driver \n", 
							( pIrpSp - 1 )->DeviceObject ); 
						
						g_CompletionIrpCount ++;
						DebugPrintEx( IRP_COMPLETION_INFO, "netmon TdiFilterSyncSendProcess  completion count++ %d\n", g_CompletionIrpCount );
						IoCallDriver( pIrpSp->DeviceObject, pIrp );
						ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
					}
					else
					{
						DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl can't allocate completion wrap, call pdo 0x%0.8x driver \n", 
							( pIrpSp - 1 )->DeviceObject ); 

						IoCallDriver( pIrpSp->DeviceObject, pIrp );
					}
					
					goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
				}

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl irp is not associated current stack location is %d\n", 
					pIrp->CurrentLocation );

				if( 1 >= pIrp->CurrentLocation )
				{
					ASSERT( FALSE );
					goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
				}

				pCompletionWrap = ( PTDI_COMPLETION_WRAP )ExAllocateFromNPagedLookasideList( &g_CompletionWrapList );

				if( NULL == pCompletionWrap )
				{
					goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
				}

				pCompletionWrap->bSendOpera = TRUE;
				pCompletionWrap->bWrap = FALSE;
				pCompletionWrap->bAssocIrp = FALSE;
				pCompletionWrap->pEProcess = pProcessNetWorkTrafficInfo->pEProcess;
				pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;

				IoCopyCurrentIrpStackLocationToNext( pIrp );

				IoSetCompletionRoutine( pIrp, 
					TdiFilterCompletion, 
					pCompletionWrap, 
					TRUE, 
					TRUE, 
					TRUE
					);

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl add completion wrap, call pdo deivce 0x%0.8x driver\n", 
					pDeviceExtension->pTdiDeviceObject );

				IoSetCancelRoutine( pIrp, NULL );

				key.quad_part = make_hash_key( 0, ( DWORD )pIrp );
				DebugPrintEx( IRP_CANCEL_INFO, "netmon ThreadSendingSpeedControl del_hash_item 0x%0.8x \n", pIrp );
				//KdBreakPoint();
				nRet = del_hash_item( &g_MasterIrpHash, key, NULL );
				DebugPrintEx( IRP_CANCEL_INFO, "netmon ThreadSendingSpeedControl del_hash_item 0x%0.8x return 0x%0.8x\n", pIrp, nRet );
				//ASSERT( 0 <= nRet );

				g_CompletionIrpCount ++;
				DebugPrintEx( IRP_COMPLETION_INFO, "netmon ThreadSendingSpeedControl  completion count++ %d\n", g_CompletionIrpCount );
				IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );
				ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
				goto RELEASE_PROCESS_IO_INFO_GET_NEXT;

SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC:
				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC\n"  );

				IoSkipCurrentIrpStackLocation( pIrp );

//CALL_PDO_DEVICE_DRIVER:
				IoCallDriver( pDeviceExtension->pTdiDeviceObject, pIrp );

RELEASE_PROCESS_IO_INFO_GET_NEXT:

				DebugPrintEx( SEND_SPEED_CONTROL_INFO, "netmon ThreadSendingSpeedControl RELEASE_PROCESS_IO_INFO_GET_NEXT\n"  );
				ReleaseProcessNetWorkTrafficInfo( pProcessNetWorkTrafficInfo );
				continue;
			}
		}

		PsTerminateSystemThread( STATUS_SUCCESS );
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	InterlockedExchange( &g_bThreadsRunning, FALSE );
	//	PsTerminateSystemThread( STATUS_SUCCESS );
	//	return;
	//}
}

VOID ThreadUpdateProcessIoState( PVOID pParam )
{
	NTSTATUS ntStatus;
	DWORD dwProcessInfoLength;
	PUNICODE_STRING ProcessImageName;
	PSYSTEM_PROCESSES pSystemProcesses;
	PPROCESS_INFORMATION_RECORD pProcessInformation;
	PPROCESS_INFORMATION_LIST_ENTRY pProcessInfoListEntry;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	DWORD dwProcessId;
	PSYSTEM_PROCESSES pSystemProcess;
	BYTE OldIrql;
	PLIST_ENTRY pListEntry;
	UNICODE_STRING ProcessImageFilePath;
	CHAR bProcessInfoFinded;
	LARGE_INTEGER SendingSpeed;
	BOOL bStopRecv;
	BOOL bStopSend;

	ProcessImageName = NULL;
	pSystemProcesses = NULL;

	for( ; ; )
	{
		DebugPrintEx( PROCESS_COMMON_INFO,  "netmon ThreadUpdateProcessIoState wait new process\n" );
		//KdBreakPoint();
		if( TRUE == g_bThreadUpdateConfigStop )
		{
			break;
		};

		ASSERT( KeGetCurrentIrql() <= DISPATCH_LEVEL );
		KeWaitForSingleObject( &g_EventProcessInformationAdded, Executive, KernelMode, FALSE, NULL ); //Waiting util process control information or process netword record added, deleted.

		for( ; ; )
		{
			ntStatus = ZwQuerySystemInformation( 
				SystemProcessInformation, 
				NULL, 
				0, 
				&dwProcessInfoLength 
				);

			if( STATUS_INFO_LENGTH_MISMATCH != ntStatus )
			{
				break;
			}

			if( NULL != pSystemProcesses )
			{
				ExFreePoolWithTag( pSystemProcesses, 0 );
			}

			pSystemProcesses = AllocZeroPoolWithTag( NonPagedPool, dwProcessInfoLength );
			if( NULL == pSystemProcesses )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			ntStatus = ZwQuerySystemInformation( SystemProcessInformation, 
				pSystemProcesses, 
				dwProcessInfoLength, 
				&dwProcessInfoLength );

			if( STATUS_INFO_LENGTH_MISMATCH != ntStatus )
			{
				break;
			}
		}

RELEASE_SYSTEM_PROCESSES_BUFF_WAIT_NEXT_PROCESS:
		if( !NT_SUCCESS( ntStatus ) )
		{
			if( NULL != pSystemProcesses )
			{
				ExFreePoolWithTag( pSystemProcesses, 0 );
				pSystemProcesses = NULL;
			}
			continue;
		}

		if( NULL == ProcessImageName )
		{
			ProcessImageName = AllocZeroPoolWithTag( 
				NonPagedPool, 
				PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH 
				);
			if( NULL == ProcessImageName )
			{
				goto RELEASE_SYSTEM_PROCESSES_BUFF_WAIT_NEXT_PROCESS;
			}
		}

		pSystemProcess = pSystemProcesses;

		for( ; ; )
		{
			dwProcessId = pSystemProcess->ProcessId;

			if( dwProcessId == SYSTEM_IDLE_PROCESS_ID || 
				dwProcessId == SYSTEM_SYSTEM_PROCESS_ID )
			{
				goto LOCATE_NEXT_SYSTEM_PROCESS;
			}

			RtlZeroMemory( ProcessImageName, PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH );

			ntStatus = GetProcessImagePath( 
				pSystemProcess->ProcessId, 
				ProcessImageName, 
				PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH 
				);

			if( !NT_SUCCESS( ntStatus ) )
			{
				goto LOCATE_NEXT_SYSTEM_PROCESS;
			}

			bProcessInfoFinded = FALSE;

			KeEnterCriticalRegion();
			ExAcquireResourceExclusive( &g_SyncResource, TRUE );

			pListEntry = g_ProcessInformationList.Flink;

			for( ; ; )
			{
				if( pListEntry == &g_ProcessInformationList )
				{
					break;
				}

				pProcessInfoListEntry = ( PPROCESS_INFORMATION_LIST_ENTRY )pListEntry;
				pProcessInformation = pProcessInfoListEntry->pProcessInformation;

				RtlInitUnicodeString( &ProcessImageFilePath, pProcessInformation->szNativeImageFileName );

				if( TRUE == RtlEqualUnicodeString( 
					&ProcessImageFilePath, 
					ProcessImageName, 
					TRUE
					) )
				{
					SendingSpeed.QuadPart = pProcessInformation->SendingSpeed.QuadPart;
					bStopRecv = pProcessInformation->bStopRecv;
					bStopSend = pProcessInformation->bStopSend;

					bProcessInfoFinded = TRUE;
					break;						
				}

				pListEntry = pListEntry->Flink;
			}

			ExReleaseResource( &g_SyncResource );
			KeLeaveCriticalRegion();

			DebugPrintEx( PROCESS_COMMON_INFO, "netmon ThreadUpdateProcessIoState KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
			KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );

			pListEntry = g_ProcessIoInfoList.Flink;

			for( ; ; )
			{
				if( pListEntry == &g_ProcessIoInfoList )
				{
					break;
				}

				pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;

				if( pProcessNetWorkTrafficInfo->dwProcessId == pSystemProcess->ProcessId )
				{
					LARGE_INTEGER InitializeValue;

					if( TRUE == bProcessInfoFinded )
					{
	
						pProcessNetWorkTrafficInfo->bStopRecv = bStopRecv;
						pProcessNetWorkTrafficInfo->bStopSend = bStopSend;

						if( 0 == SendingSpeed.QuadPart )
						{
							InitializeValue.LowPart = 0xFFFFFFFF;
							InitializeValue.HighPart = 0x7FFFFFFF;
						}
						else
						{
							InitializeValue.QuadPart = SendingSpeed.QuadPart;
						}

						INTERLOCKED_COMPARE_EXCHANGE64( &pProcessNetWorkTrafficInfo->SendingSpeed, InitializeValue );
					}
					else
					{

						pProcessNetWorkTrafficInfo->bStopRecv = FALSE;
						pProcessNetWorkTrafficInfo->bStopSend = FALSE;

						InitializeValue.LowPart = 0xFFFFFFFF;
						InitializeValue.HighPart = 0x7FFFFFFF;

						INTERLOCKED_COMPARE_EXCHANGE64( &pProcessNetWorkTrafficInfo->SendingSpeed, InitializeValue );
					}

					break; //Only one process control information and one process network traffic record match one process.
				}
				pListEntry = pListEntry->Flink;
			}

			KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
			DebugPrintEx( PROCESS_COMMON_INFO, "netmon ThreadUpdateProcessIoState KeReleaseSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );

LOCATE_NEXT_SYSTEM_PROCESS:
			if( 0 == pSystemProcess->NextEntryDelta )
			{
				break;
			}
			pSystemProcess = ( PSYSTEM_PROCESSES )( ( PBYTE )pSystemProcess + pSystemProcess->NextEntryDelta );
			ASSERT( TRUE == MmIsAddressValid( pSystemProcess ) );
		} // foreach system process.
	}

	if( NULL != ProcessImageName )
	{
		ExFreePoolWithTag( ProcessImageName, 0 );
	}

	if( NULL != pSystemProcesses )
	{
		ExFreePoolWithTag( pSystemProcesses, 0 );
	}

	PsTerminateSystemThread( STATUS_SUCCESS );
}

VOID TimerDpcProcess( PKDPC pDpc, PVOID pEProcess, PVOID SystemArgument1 , PVOID SystemArgument2 )
{
	PLIST_ENTRY pListEntry;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	LARGE_INTEGER UpdatedValue;

	DebugPrintEx( TIMER_DPC_INFO, "Enter netmon TimerDpcProcess" );

	KeAcquireSpinLockAtDpcLevel( &g_SpLockProcessNetWorkTrafficInfo );

	pListEntry = g_ProcessIoInfoList.Flink;

	for( ; ; )
	{
		if( pListEntry == &g_ProcessIoInfoList )
		{
			break;
		}

		pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;

		if( pProcessNetWorkTrafficInfo->pEProcess == pEProcess )
		{
			InterlockedExchangeAdd( &pProcessNetWorkTrafficInfo->dwRefCount, 1 );
			
			UpdatedValue.QuadPart = 0;

			INTERLOCKED_COMPARE_EXCHANGE64( 
				&pProcessNetWorkTrafficInfo->SendedSizeOneSec, 
				UpdatedValue 
				);

			if( pProcessNetWorkTrafficInfo->AllSuccSendedDataSize.QuadPart >= 
				pProcessNetWorkTrafficInfo->AllSuccSendedDataSizePrev.QuadPart )
			{
				UpdatedValue.QuadPart = pProcessNetWorkTrafficInfo->AllSuccSendedDataSize.QuadPart - 
					pProcessNetWorkTrafficInfo->AllSuccSendedDataSizePrev.QuadPart;

				INTERLOCKED_COMPARE_EXCHANGE64( 
					&pProcessNetWorkTrafficInfo->SuccSendedDataSizeOnce, 
					UpdatedValue 
					);
			}

			INTERLOCKED_COMPARE_EXCHANGE64( 
				&pProcessNetWorkTrafficInfo->AllSuccSendedDataSizePrev, 
				pProcessNetWorkTrafficInfo->AllSuccSendedDataSize 
				);

			if( pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize.QuadPart >= 
				pProcessNetWorkTrafficInfo->AllSuccRecvedDataSizePrev.QuadPart )
			{
				UpdatedValue.QuadPart = pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize.QuadPart - 
					pProcessNetWorkTrafficInfo->AllSuccRecvedDataSizePrev.QuadPart;

				INTERLOCKED_COMPARE_EXCHANGE64( 
					&pProcessNetWorkTrafficInfo->SuccRecvedDataSizeOnce, 
					UpdatedValue 
					);
			}

			INTERLOCKED_COMPARE_EXCHANGE64( 
				&pProcessNetWorkTrafficInfo->AllSuccRecvedDataSizePrev, 
				pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize 
				);

			KeSetTimer( pProcessNetWorkTrafficInfo->pTimer, 
				g_TimerElapse, 
				pProcessNetWorkTrafficInfo->pDpc ); //Loop the timer

			InterlockedExchangeAdd( &pProcessNetWorkTrafficInfo->dwRefCount, -1 );
			break;
		}
		pListEntry = pListEntry->Flink;
	}

	KeReleaseSpinLockFromDpcLevel( &g_SpLockProcessNetWorkTrafficInfo );

	DebugPrintEx( TIMER_DPC_INFO, "Leave netmon TimerDpcProcess" );
}

VOID DeleteProcessIoInfo( DWORD dwParentId, DWORD dwProcessId, BOOL bCreate )
{
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;

	//KdBreakPoint();

	DebugPrintEx( PROCESS_COMMON_INFO, "netmon enter DeleteProcessIoInfo \n" );
	if ( FALSE == bCreate )
	{
		DebugPrintEx( PROCESS_COMMON_INFO, "netmon DeleteProcessIoInfo KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
		KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );
		//DebugPrintEx( PROCESS_COMMON_INFO, "netmon DeleteProcessIoInfo KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo end \n" );

		pListEntry = g_ProcessIoInfoList.Flink;
		
		for( ; ; )
		{
			//DebugPrintEx( PROCESS_COMMON_INFO, "netmon DeleteProcessIoInfo find process info: 0x%0.8x list head 0x%0.8x \n", pListEntry, &g_ProcessIoInfoList );
			if( pListEntry == &g_ProcessIoInfoList )
			{
				break;
			}

			pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;
			if ( pProcessNetWorkTrafficInfo->dwProcessId == dwProcessId )
			{
				DWORD dwCurRefCount;

				RemoveEntryList( pListEntry );

				KeCancelTimer( pProcessNetWorkTrafficInfo->pTimer );
				
				dwCurRefCount = InterlockedExchangeAdd( &pProcessNetWorkTrafficInfo->dwRefCount, -1 );
				if ( 1 == dwCurRefCount )
				{
					ExFreePoolWithTag( pProcessNetWorkTrafficInfo->pDpc, 0 );
					ExFreePoolWithTag( pProcessNetWorkTrafficInfo->pTimer, 0 );
					ExFreePoolWithTag( pProcessNetWorkTrafficInfo, 0 );
				}
				else
				{
					ASSERT( dwCurRefCount > 1 );
				}
				break;
			}
			
			pListEntry = pListEntry->Flink;
		}

		KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
		DebugPrintEx( PROCESS_COMMON_INFO, "netmon DeleteProcessIoInfo KeReleaseSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
	}

	DebugPrintEx( PROCESS_COMMON_INFO, "netmon leave DeleteProcessIoInfo \n" );
}

NTSTATUS GetAllProcessesIoInformation( LPVOID *pOutput, DWORD dwInputBuffLength, DWORD *pAllInfoLength )
{
	NTSTATUS ntStatus;
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	DWORD dwCopiedLength;
	PPROCESS_IO_INFO_OUTPUT pProcessIoInfoOutput;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;

	if( dwBPFlag & BP_ON_GET_ALL_PROCESS_IO )
	{
		KdBreakPoint();
	}

	if( NULL == pOutput ||
		NULL == pAllInfoLength )
	{
		return STATUS_INVALID_PARAMETER;
	}

	//_try
	//{
		//DebugPrintEx( OUTPUT_ALL_PROCESS_IO_INFO,  "netmon GetAllProcessesIoInformation KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
		KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );

		pProcessIoInfoOutput = ( PPROCESS_IO_INFO_OUTPUT )pOutput;

		pListEntry = g_ProcessIoInfoList.Blink;
		dwCopiedLength = 0;
		ntStatus = STATUS_SUCCESS;

		for( ; ; )
		{
			if( pListEntry == &g_ProcessIoInfoList )
			{
				break;
			}

			pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;

			if ( dwCopiedLength + sizeof( PROCESS_IO_INFO_OUTPUT ) > dwInputBuffLength )
			{
				ntStatus = STATUS_BUFFER_TOO_SMALL;
				*pAllInfoLength = 0;
				break;
			}

			DebugPrintEx( OUTPUT_ALL_PROCESS_IO_INFO,  "netmon GetAllProcessesIoInformation  process id: %d \n",  //, sending speed: %d, all received data size: %d, all sended data size: %d \n stop recv: %d, stop send: %d, current recv speed: %d, current send speed: %d \n", 	
				pProcessNetWorkTrafficInfo->dwProcessId 
				//pProcessNetWorkTrafficInfo->SendingSpeed.LowPart, 
				//pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize.LowPart, 
				//pProcessNetWorkTrafficInfo->AllSuccSendedDataSize.LowPart, 
				//pProcessNetWorkTrafficInfo->bStopRecv, 
				//pProcessNetWorkTrafficInfo->bStopSend, 
				//pProcessNetWorkTrafficInfo->SuccRecvedDataSizeOnce.LowPart, 
				//pProcessNetWorkTrafficInfo->SuccSendedDataSizeOnce.LowPart 
				);

			pProcessIoInfoOutput->dwProcessId = pProcessNetWorkTrafficInfo->dwProcessId;
			pProcessIoInfoOutput->AllSuccSendedDataSize.QuadPart = pProcessNetWorkTrafficInfo->AllSuccSendedDataSize.QuadPart;
			pProcessIoInfoOutput->AllSuccRecvedDataSize.QuadPart = pProcessNetWorkTrafficInfo->AllSuccRecvedDataSizePrev.QuadPart;
			pProcessIoInfoOutput->bStopSend = pProcessNetWorkTrafficInfo->bStopSend;
			pProcessIoInfoOutput->bStopRecv = pProcessNetWorkTrafficInfo->bStopRecv;
			pProcessIoInfoOutput->SendingSpeed.QuadPart = pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart;
			pProcessIoInfoOutput->SuccSendedDataSizeOnce.QuadPart = pProcessNetWorkTrafficInfo->SuccSendedDataSizeOnce.QuadPart;
			pProcessIoInfoOutput->SuccRecvedDataSizeOnce.QuadPart = pProcessNetWorkTrafficInfo->SuccRecvedDataSizeOnce.QuadPart;

			pProcessIoInfoOutput ++;
			dwCopiedLength += sizeof( PROCESS_IO_INFO_OUTPUT );

			pListEntry = pListEntry->Blink;
		}

		KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
		//DebugPrintEx( OUTPUT_ALL_PROCESS_IO_INFO, "netmon GetAllProcessesIoInformation KeReleaseSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
		*pAllInfoLength = dwCopiedLength;
	//}
	//_except(  EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}
	return ntStatus;
}

NTSTATUS GetAllProcessesInformation( PPROCESS_INFORMATION_RECORD pAllProcessInfomation, DWORD dwBufferLength, DWORD *pAllInfoLength )
{
	NTSTATUS ntStatus;
	PLIST_ENTRY pListEntry;
	PPROCESS_INFORMATION_LIST_ENTRY pProcessInformationList;
	PPROCESS_INFORMATION_RECORD pProcessInformation;
	DWORD dwListSize;
	PPROCESS_INFORMATION_RECORD pPrcessInformationOutput;

	if( dwBPFlag & BP_ON_GET_ALL_PROCESS_CONTROL )
	{
		KdBreakPoint();
	}

	if ( NULL == pAllProcessInfomation || 
		0 == pAllInfoLength )
	{
		return STATUS_INVALID_PARAMETER;
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite( &g_SyncResource, TRUE );

	ntStatus = STATUS_SUCCESS;

	dwListSize = 0;

	//_try
	//{
		for( pListEntry = g_ProcessInformationList.Flink; pListEntry != &g_ProcessInformationList; pListEntry = pListEntry->Flink )
		{
			dwListSize ++;
		}

		if( dwBufferLength < sizeof( PROCESS_INFORMATION_RECORD ) * dwListSize )
		{
			ntStatus = STATUS_BUFFER_TOO_SMALL;
			goto RETURN_;
		}

		*pAllInfoLength = 0;
		pPrcessInformationOutput = pAllProcessInfomation;

		pListEntry = g_ProcessInformationList.Flink;

		for( ; ; )
		{
			if( pListEntry == &g_ProcessInformationList )
			{
				break;
			}

			pProcessInformationList = ( PPROCESS_INFORMATION_LIST_ENTRY )pListEntry;
			pProcessInformation = pProcessInformationList->pProcessInformation;

			DebugPrintEx( OUTPUT_ALL_PROCESS_CONTROL_INFO, "Get process control setting: \n, Remove %d, StopRecv %d, StopSend %d, SendingSpeed: %d \n ImagePath %ws \n", 
				pProcessInformation->bRemove,
				pProcessInformation->bStopRecv, 
				pProcessInformation->bStopSend, 
				pProcessInformation->SendingSpeed, 
				pProcessInformation->szNativeImageFileName
				);

			RtlCopyMemory( pPrcessInformationOutput, pProcessInformationList->pProcessInformation, sizeof( PROCESS_INFORMATION_RECORD ) );
			*pAllInfoLength += sizeof( PROCESS_INFORMATION_RECORD );
			pPrcessInformationOutput ++;

			pListEntry = pListEntry->Flink;
		}

		ntStatus = STATUS_SUCCESS;

		//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}

RETURN_:
	ExReleaseResourceLite( &g_SyncResource );
	KeLeaveCriticalRegion();

	return ntStatus;
}

#include <ntstatus.h>
NTSTATUS ReleaseAllProcessesInformation()
{
	PPROCESS_INFORMATION_LIST_ENTRY pProcessInformationList;

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite( &g_SyncResource, TRUE );

	for( ; ; )
	{
		if( TRUE == IsListEmpty( &g_ProcessInformationList ) )
		{
			break;
		}
		pProcessInformationList = ( PPROCESS_INFORMATION_LIST_ENTRY )RemoveHeadList( &g_ProcessInformationList );
		ExFreePoolWithTag( pProcessInformationList->pProcessInformation, 0);
		ExFreePoolWithTag( pProcessInformationList, 0 );
	}

	ExReleaseResourceLite( &g_SyncResource );
	KeLeaveCriticalRegion();
	KeSetEvent( &g_EventProcessInformationAdded, 0, FALSE );

	return STATUS_SUCCESS;
}

BOOL IsDriverDevice( PDEVICE_OBJECT pDeviceObject )
{
	if( NULL == pDeviceObject )
	{
		return FALSE;
	}

	if( pDeviceObject == g_DevTdiFilter || 
		pDeviceObject == g_FilterDeviceForDeviceTcp || 
		pDeviceObject == g_FilterDeviceForDeviceUdp )
	{
		return TRUE;
	}

	return FALSE;
}

NTSTATUS StartWorkThreadManageProcessInfo( 
	PPROCESS_INFORMATION_RECORD pProcessInformationFind, 
	DWORD dwInputBufferLength 
	)
{
	NTSTATUS ntStatus;
	PPROCESS_INFORMATION_LIST_ENTRY pProcessInformationLink;
	PPROCESS_INFORMATION_RECORD pProcessInformation;
	HANDLE hSystemThread;
	UNICODE_STRING ProcessImageFilePathFind;
	UNICODE_STRING ProcessImageFilePath;
	PLIST_ENTRY pListEntry;

	ntStatus = STATUS_SUCCESS;

	if( dwBPFlag & BP_ON_ADD_PROCESS_CONTROL )
	{
		KdBreakPoint();
	}

	//_try
	//{
	DebugPrintEx( PROCESS_START_THREAD_INFO,  "netmon Entry StartWorkThreadManageProcessInfo input length is %d\n", dwInputBufferLength );
		if( TRUE == InterlockedExchangeAdd( &g_bBeginStartThreads, 0 ) )
		{
			if( FALSE == InterlockedExchangeAdd( &g_bThreadsRunning, 0 ) )
			{
				return STATUS_UNSUCCESSFUL;
			}
		}

		if( NULL == pProcessInformationFind )
		{
			return STATUS_INVALID_PARAMETER;
		}

		if( sizeof( PROCESS_INFORMATION_RECORD ) != dwInputBufferLength )
		{
			return STATUS_INVALID_PARAMETER;
		}

		if( NULL == pProcessInformationFind->szNativeImageFileName )
		{
			return STATUS_INVALID_PARAMETER;
		}

		if( L'\0' != pProcessInformationFind->szNativeImageFileName[ PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH - 1 ] )
		{
			return STATUS_INVALID_PARAMETER;
		}

		if( FALSE == InterlockedExchangeAdd( &g_bBeginStartThreads, 0 ) )
		{
			InterlockedExchange( &g_bBeginStartThreads, TRUE );

			/*	NTSTATUS 
			PsCreateSystemThread(
			OUT PHANDLE  ThreadHandle,
			IN ULONG  DesiredAccess,
			IN POBJECT_ATTRIBUTES  ObjectAttributes  OPTIONAL,
			IN HANDLE  ProcessHandle  OPTIONAL,
			OUT PCLIENT_ID  ClientId  OPTIONAL,
			IN PKSTART_ROUTINE  StartRoutine,
			IN PVOID  StartContext
			);*/

			DebugPrintEx( PROCESS_START_THREAD_INFO,  "netmon StartWorkThreadManageProcessInfo start ThreadUpdateProcessIoState \n" );

			if( NULL == ThreadUpdateConfig )
			{
				ntStatus = CreateWorkThread( ThreadUpdateProcessIoState, 
					NULL, 
					&ThreadUpdateConfig
					);

				if( !NT_SUCCESS( ntStatus ) )
				{
					InterlockedExchange( &g_bBeginStartThreads, FALSE );
					return ntStatus;
				}
			}

			DebugPrintEx( PROCESS_START_THREAD_INFO,  "netmon StartWorkThreadManageProcessInfo start ThreadSendingSpeedControl \n" );

			if( NULL == ThreadProcessIrp )
			{
				ntStatus = CreateWorkThread( ThreadSendingSpeedControl, 
					NULL, 
					&ThreadProcessIrp
					);

				if( !NT_SUCCESS( ntStatus ) )
				{
					InterlockedExchange( &g_bBeginStartThreads, FALSE );
					return ntStatus;
				}
			}

			InterlockedExchange( &g_bThreadsRunning, TRUE );
		}

		RtlInitUnicodeString( &ProcessImageFilePathFind, pProcessInformationFind->szNativeImageFileName );
		
		DebugPrintEx( PROCESS_START_THREAD_INFO, "netmon StartWorkThreadManageProcessInfo process information modifing  stop recv: %d, stop send %d, send speed: %d\n", 
			pProcessInformationFind->bStopRecv, 
			pProcessInformationFind->bStopSend, 
			pProcessInformationFind->SendingSpeed.LowPart 
			);

		KeEnterCriticalRegion();
		ExAcquireResourceExclusive( &g_SyncResource, TRUE );

		pListEntry = g_ProcessInformationList.Flink;

		for( ; ; )
		{
			if( pListEntry == &g_ProcessInformationList )
			{
				break;
			}

			pProcessInformationLink = ( PPROCESS_INFORMATION_LIST_ENTRY )pListEntry;
			pProcessInformation = pProcessInformationLink->pProcessInformation;
			RtlInitUnicodeString( &ProcessImageFilePath, pProcessInformation->szNativeImageFileName );

			DebugPrintEx( PROCESS_START_THREAD_INFO,  "netmon StartWorkThreadManageProcessInfo find process information find image path: %wZ, located image path: %wZ\n", 
				&ProcessImageFilePathFind, 
				&ProcessImageFilePath );

			if( TRUE == RtlEqualUnicodeString( &ProcessImageFilePath, 
				&ProcessImageFilePathFind, TRUE ) )
			{
				if( FALSE == pProcessInformationFind->bRemove )
				{
					RtlCopyMemory( pProcessInformation, pProcessInformationFind, sizeof( PROCESS_INFORMATION_RECORD ) );
					KeSetEvent( &g_EventProcessInformationAdded, 0, FALSE );

					ExReleaseResource( &g_SyncResource );
					KeLeaveCriticalRegion();
					return ntStatus;
				}

				RemoveEntryList( pListEntry );

				ExFreePoolWithTag( pProcessInformation, 0 );
				ExFreePoolWithTag( pProcessInformationLink, 0 );

				KeSetEvent( &g_EventProcessInformationAdded, 0, FALSE );

				ExReleaseResource( &g_SyncResource );
				KeLeaveCriticalRegion();
				return ntStatus;
			}

			pListEntry = pListEntry->Flink;
		}

		DebugPrintEx( PROCESS_START_THREAD_INFO,  "netmon StartWorkThreadManageProcessInfo process information not find \n" );
		if( FALSE != pProcessInformationFind->bRemove )
		{
			ExReleaseResource( &g_SyncResource );
			KeLeaveCriticalRegion();
			return ntStatus;
		}

		pProcessInformationLink = ( PPROCESS_INFORMATION_LIST_ENTRY )AllocZeroPoolWithTag( PagedPool, sizeof( PROCESS_INFORMATION_LIST_ENTRY ) );

		if( NULL == pProcessInformationLink )
		{
			ExReleaseResource( &g_SyncResource );
			KeLeaveCriticalRegion();

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		pProcessInformation = ( PPROCESS_INFORMATION_RECORD )AllocZeroPoolWithTag( PagedPool, sizeof( PROCESS_INFORMATION_RECORD ) );

		if( NULL == pProcessInformation )
		{
			ExFreePoolWithTag( pProcessInformationLink, 0 );

			ExReleaseResource( &g_SyncResource );
			KeLeaveCriticalRegion();

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlCopyMemory( pProcessInformation, pProcessInformationFind, sizeof( PROCESS_INFORMATION_RECORD ) );

		pProcessInformationLink->pProcessInformation = pProcessInformation;

		DebugPrintEx( PROCESS_START_THREAD_INFO,  "netmon StartWorkThreadManageProcessInfo insert new process information \n" );

		InsertTailList( &g_ProcessInformationList, ( PLIST_ENTRY )pProcessInformationLink );

		KeSetEvent( &g_EventProcessInformationAdded, 0, FALSE );

		ExReleaseResource( &g_SyncResource );
		KeLeaveCriticalRegion();
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}

	return ntStatus;
}

NTSTATUS  AttachToTdiDevice( PDRIVER_OBJECT DriverObject, PUNICODE_STRING TargetDeviceName, PDEVICE_OBJECT *ppDeviceObject )
{
	NTSTATUS ntStatus;
	PDEVICE_OBJECT DeviceObject;

	DeviceObject = NULL;

	if( NULL == DriverObject || 
		NULL == TargetDeviceName || 
		NULL == ppDeviceObject )
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto EXIT;
	}

	//_try
	//{
		ntStatus = IoCreateDevice( 
			DriverObject, 
			sizeof( TDI_FILTER_DEVICE_EXTENSION ), 
			NULL, 
			FILE_DEVICE_NETWORK, 
			0, 
			0, 
			&DeviceObject 
			);

		if( NT_SUCCESS( ntStatus ) )
		{
			DeviceObject->Flags |= DO_DIRECT_IO;
			ntStatus = IoAttachDevice( 
				DeviceObject, 
				TargetDeviceName, 
				( PDEVICE_OBJECT* )DeviceObject->DeviceExtension 
				);

			if( NT_SUCCESS( ntStatus ) )
				*ppDeviceObject = DeviceObject;
		}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}

EXIT:
	if ( !NT_SUCCESS( ntStatus ) )
	{
		if( NULL != DeviceObject )
			IoDeleteDevice( DeviceObject );
	}
	return ntStatus;
}

PPROCESS_NETWORK_TRAFFIC GetProcessNetWorkTrafficInfoFromEProcess( PEPROCESS pEProcess )
{
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;
	PPROCESS_NETWORK_TRAFFIC pNewProcessNetWorkTrafficInfo;

	ASSERT( NULL != pEProcess );

	if ( NULL == pEProcess )
		return NULL;

	DebugPrintEx( PROCESS_NEW_IO_INFO, "netmon GetProcessNetWorkTrafficInfoFromEProcess KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );
	KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );
	
	//_try
	//{
		pListEntry = g_ProcessIoInfoList.Flink;

		for ( ; ; )
		{
			if( pListEntry == &g_ProcessIoInfoList )
			{
				break;
			}

			pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;

			if( pProcessNetWorkTrafficInfo->pEProcess == pEProcess )
			{
				ASSERT( pProcessNetWorkTrafficInfo->dwRefCount >= 1 );

				InterlockedExchangeAdd( &pProcessNetWorkTrafficInfo->dwRefCount, 1 );
				KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
				return pProcessNetWorkTrafficInfo;
			}

			pListEntry = pListEntry->Flink;
		}

		pNewProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )AllocZeroPoolWithTag( NonPagedPool, sizeof( PROCESS_NETWORK_TRAFFIC ) );
		if( NULL == pNewProcessNetWorkTrafficInfo )
		{
			goto RETURN_ERROR;
		}

		pNewProcessNetWorkTrafficInfo->pTimer = AllocZeroPoolWithTag( NonPagedPool, sizeof( KTIMER ) );
		pNewProcessNetWorkTrafficInfo->pDpc = AllocZeroPoolWithTag( NonPagedPool, sizeof( KDPC ) );

		if( NULL == pProcessNetWorkTrafficInfo->pTimer || 
			NULL == pProcessNetWorkTrafficInfo->pDpc )
		{
			goto RETURN_ERROR;
		}

		//pNewProcessNetWorkTrafficInfo->IrpListLock = 0;

		KeInitializeSpinLock( &pNewProcessNetWorkTrafficInfo->IrpListLock );

		InitializeListHead( &pNewProcessNetWorkTrafficInfo->IrpList );

		KeInitializeTimer( pNewProcessNetWorkTrafficInfo->pTimer );
		KeInitializeDpc( pNewProcessNetWorkTrafficInfo->pDpc, TimerDpcProcess, ( PVOID )pEProcess );
		KeSetTimer( pNewProcessNetWorkTrafficInfo->pTimer, g_TimerElapse, pNewProcessNetWorkTrafficInfo->pDpc );
		pNewProcessNetWorkTrafficInfo->pEProcess = pEProcess;
		pNewProcessNetWorkTrafficInfo->dwProcessId = ( DWORD )PsGetProcessId( pEProcess );

		pNewProcessNetWorkTrafficInfo->SendingSpeed.LowPart = 1024; //0xFFFFFFFF;
		pNewProcessNetWorkTrafficInfo->SendingSpeed.HighPart = 0; //0x7FFFFFFF;

		pNewProcessNetWorkTrafficInfo->dwRefCount = PROCESS_NETWORK_TRAFFIC_INIT_REFERRENCE;
		InsertHeadList( &g_ProcessIoInfoList, &pNewProcessNetWorkTrafficInfo->ProcessIoList );
		DebugPrintEx( PROCESS_NEW_IO_INFO, "netmon Insert new process io information 0x%0.8x \n", pNewProcessNetWorkTrafficInfo );

		KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );

		if( TRUE == InterlockedExchangeAdd( &g_bThreadsRunning, 0 ) )
		{
			KeSetEvent( &g_EventProcessInformationAdded, 0, FALSE );
		}

		return pNewProcessNetWorkTrafficInfo;

RETURN_ERROR:
		if( NULL != pNewProcessNetWorkTrafficInfo )
		{
			if ( NULL != pNewProcessNetWorkTrafficInfo->pDpc )
			{
				ExFreePoolWithTag( pNewProcessNetWorkTrafficInfo->pDpc, 0 );;
			}

			if ( NULL != pNewProcessNetWorkTrafficInfo->pTimer )
			{
				ExFreePoolWithTag( pNewProcessNetWorkTrafficInfo->pTimer, 0 );
			}

			ExFreePoolWithTag( pNewProcessNetWorkTrafficInfo, 0 );
		}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//}

	KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );

	return NULL;
}

PPROCESS_NETWORK_TRAFFIC  ReferenceProcessNetWorkTrafficInfo( PEPROCESS pEProcess )
{
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	NTSTATUS ntStatus;
	PPROCESS_NETWORK_TRAFFIC pProcessNetWorkTrafficInfo;

	DebugPrintEx( PROCESS_COMMON_INFO,  "netmon ReferenceProcessNetWorkTrafficInfo KeAcquireSpinLock g_SpLockProcessNetWorkTrafficInfo \n" );

	KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );

	pListEntry = g_ProcessIoInfoList.Flink;

	for ( ; ; )
	{
		ASSERT( NULL != pListEntry );

		if( pListEntry == &g_ProcessIoInfoList )
		{
			pProcessNetWorkTrafficInfo = NULL;
			break;
		}

		pProcessNetWorkTrafficInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;
		
		ASSERT( NULL != pProcessNetWorkTrafficInfo->pEProcess );

		if ( pProcessNetWorkTrafficInfo->pEProcess == pEProcess )
		{
			InterlockedExchangeAdd( &pProcessNetWorkTrafficInfo->dwRefCount, 1 );
			break;
		}

		pListEntry = pListEntry->Flink;
	}

	KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
	return pProcessNetWorkTrafficInfo;
}

void ReleaseAllProcessNetWorkTrafficInfo()
{
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PLIST_ENTRY pListEntryPrev;
	PPROCESS_NETWORK_TRAFFIC pProcessIoInfo;

	KeAcquireSpinLock( &g_SpLockProcessNetWorkTrafficInfo, &OldIrql );

	pListEntry = g_ProcessIoInfoList.Flink;

	for( ; ; )
	{
		DWORD dwCurRefCount;
		if( pListEntry == &g_ProcessIoInfoList )
		{
			break;
		}

		pListEntryPrev = pListEntry->Flink;

		RemoveEntryList( pListEntry );

		pProcessIoInfo = ( PPROCESS_NETWORK_TRAFFIC )pListEntry;

		ASSERT( NULL != pProcessIoInfo->pTimer );
		
		KeCancelTimer( pProcessIoInfo->pTimer );

		dwCurRefCount = InterlockedExchangeAdd( &pProcessIoInfo->dwRefCount, -1 );
		if ( 1 == dwCurRefCount )
		{
			ExFreePoolWithTag( pProcessIoInfo->pDpc, 0 );
			ExFreePoolWithTag( pProcessIoInfo->pTimer, 0 );
			ExFreePoolWithTag( pProcessIoInfo, 0 );
		}
		else
		{
			ASSERT( dwCurRefCount > 1 );
		}

		pListEntry = pListEntryPrev;
	}

	KeReleaseSpinLock( &g_SpLockProcessNetWorkTrafficInfo, OldIrql );
}

DWORD ReleaseProcessNetWorkTrafficInfo( PROCESS_NETWORK_TRAFFIC *pProcessNetWorkTrafficInfo )
{
	NTSTATUS ntStatus;
	DWORD dwCurRefCount;

	ASSERT( NULL != pProcessNetWorkTrafficInfo );
	ASSERT( TRUE == MmIsAddressValid( pProcessNetWorkTrafficInfo ) );

	dwCurRefCount = InterlockedExchangeAdd( &pProcessNetWorkTrafficInfo->dwRefCount, -1 );

	DebugPrintEx( RELEASE_PROCESS_INFO, "netmon Enter ReleaseProcessNetWorkTrafficInfo prev reference count of the process information is %d\n", 
		dwCurRefCount );

	if( 1 == dwCurRefCount )
	{
		ExFreePoolWithTag( pProcessNetWorkTrafficInfo->pDpc, 0 );
		ExFreePoolWithTag( pProcessNetWorkTrafficInfo->pTimer, 0 );
		ExFreePoolWithTag( pProcessNetWorkTrafficInfo, 0 );
	}
	else
	{
		ASSERT( dwCurRefCount > 1 );
	}

	DebugPrintEx( RELEASE_PROCESS_INFO, "netmon Leave ReleaseProcessNetWorkTrafficInfo \n" );
	return dwCurRefCount - 1;
}

NTSTATUS  EnterUserProcessReadImagePath( PEPROCESS pEProcess, PUNICODE_STRING pImageFilePath )
{
	KAPC_STATE ApcState;
	NTSTATUS ntStatus;
	CHAR bIsAttachToOtherProc;
	PPEB pPeb;
	DWORD ImageFilePathLength;
	PRTL_USER_PROCESS_PARAMETERS pProcessParameters;

	ntStatus = STATUS_SUCCESS;
	bIsAttachToOtherProc = FALSE;

	if( NULL == pEProcess || 
		NULL == pImageFilePath )
	{
		ASSERT( FALSE );
		return STATUS_INVALID_PARAMETER;
	}
	//_try
	//{
		pPeb = PsGetProcessPeb( pEProcess );

		DebugPrintEx( READ_USER_PROC_PEB_INFO, "netmon Enter EnterUserProcessReadImagePath readed peb 0x%0.8x \n", pPeb );

		if( NULL == pPeb )
		{
			return STATUS_INVALID_PARAMETER;
		}

		if( pEProcess != IoGetCurrentProcess() )
		{
			KeStackAttachProcess( pEProcess, &ApcState );
			bIsAttachToOtherProc = TRUE;
		}

		ProbeForRead( pPeb, FIELD_OFFSET( PEB, SubSystemData ), 1 );

		pProcessParameters = pPeb->ProcessParameters;

		ProbeForRead( pProcessParameters, FIELD_OFFSET( RTL_USER_PROCESS_PARAMETERS, CommandLine ), 1 );
		ProbeForRead( pProcessParameters->ImagePathName.Buffer, pProcessParameters->ImagePathName.Length, 2 );

		if ( pImageFilePath->MaximumLength < pProcessParameters->ImagePathName.Length + pImageFilePath->Length )
		{
			ntStatus= STATUS_INSUFFICIENT_RESOURCES;
		}
		else
		{
			RtlCopyMemory( ( PBYTE )pImageFilePath->Buffer + pImageFilePath->Length, pProcessParameters->ImagePathName.Buffer, pProcessParameters->ImagePathName.Length);
			pImageFilePath->Length += pProcessParameters->ImagePathName.Length;
		}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}

	if( TRUE == bIsAttachToOtherProc )
	{
		KeUnstackDetachProcess( &ApcState );
	}
	return ntStatus;
}

NTSTATUS  GetFileHandle( PHANDLE pFileHandle, PUNICODE_STRING FileName )
{
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;

	if ( NULL == pFileHandle || NULL == FileName )
	{
		return STATUS_INVALID_PARAMETER;
	}

	InitializeObjectAttributes( 
		&ObjectAttributes, 
		FileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);

	ntStatus = ZwCreateFile(
		pFileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
		NULL, 
		0 
		);

	return ntStatus;
}

NTSTATUS  QueryFileAndDirInfo( HANDLE hFile, 
									  LPCWSTR pwszFilePath, 
									  LPCWSTR pwszFileName, 
									  PFILE_BOTH_DIRECTORY_INFORMATION FileInformation, 
									  ULONG FileInformationLength )
{
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK IoStatusBlock;
	UNICODE_STRING FileName;

	if( NULL == hFile || 
		pwszFilePath > pwszFileName || 
		NULL == FileInformation || 
		0 == FileInformationLength)
	{
		return STATUS_INVALID_PARAMETER;
	}


	FileName.Length = sizeof( WCHAR ) * ( pwszFileName - pwszFilePath );
	FileName.MaximumLength = sizeof( WCHAR ) * ( pwszFileName - pwszFilePath );
	FileName.Buffer = ( LPWSTR )pwszFilePath;

	ntStatus = ZwQueryDirectoryFile
		(
		hFile,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FileInformation,
		FileInformationLength,
		FileBothDirectoryInformation,
		TRUE,
		&FileName,
		TRUE
		);
	return ntStatus;
}

LPWSTR  FindWideCharInWideString(LPCWSTR pszwString, DWORD dwLength, WCHAR wFindChar)
{
	INT32 i;
	LPWSTR pwszFinded;

	if( NULL == pszwString || 
		dwLength == 0 )
	{
		ASSERT( FALSE );
		return 0;
	}

	pwszFinded = NULL;
	for( i = 0; i < ( INT32 )dwLength; i ++ )
	{
		if( pszwString[ i ] == wFindChar )
		{
			pwszFinded = ( LPWSTR )&pszwString[i];
			break;
		}
	}

	return pwszFinded;
}

NTSTATUS  ShortPathNameToEntirePathName( PUNICODE_STRING ShortPathName, PUNICODE_STRING FullPathName )
{
	NTSTATUS ntStatus;
	UNICODE_STRING __FullPathName;
	HANDLE hFile;
	LPWSTR pwszShortPath;
	UNICODE_STRING __ShortPathName;
	LPWSTR pwszAfterSymPrefix;
	LPWSTR pwszPathDelim;
	CHAR bPathEnd;
	PFILE_BOTH_DIRECTORY_INFORMATION pFileInfo;
	DWORD dwFileNameLength;
	DWORD dwWritedLength;

	if( NULL == ShortPathName || 
		NULL == FullPathName )
	{
		return STATUS_INVALID_PARAMETER;
	}

	//_try
	//{
		if( ShortPathName->Length < FILE_SYMBLOLIC_NAME_PREFIX_SIZE || 
			ShortPathName->Buffer[ 0 ] != L'\\' || 
			ShortPathName->Buffer[ 1 ] != L'?' || 
			ShortPathName->Buffer[ 2 ] != L'?' || 
			ShortPathName->Buffer[ 3 ] != L'\\' || 
			ShortPathName->Buffer[ 5 ] != L':' || 
			ShortPathName->Buffer[ 6 ] != L'\\' )
		{
			return STATUS_INVALID_PARAMETER;
		}

		pFileInfo = NULL;
		hFile = NULL;

		__FullPathName.Length = 0;
		__FullPathName.MaximumLength = COMMON_OBJ_NAME_MAX_LENGTH;
		__FullPathName.Buffer = AllocZeroPoolWithTag( NonPagedPool, COMMON_OBJ_NAME_MAX_LENGTH );

		if( NULL == __FullPathName.Buffer )
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			goto RETURN_ERROR;
		}

		pFileInfo = AllocZeroPoolWithTag( NonPagedPool, COMMON_OBJ_NAME_MAX_LENGTH );

		if( NULL == pFileInfo )
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			goto RETURN_ERROR;
		}

		__ShortPathName.Buffer = ShortPathName->Buffer;
		__ShortPathName.Length = FILE_SYMBLOLIC_NAME_PREFIX_SIZE;
		__ShortPathName.MaximumLength = FILE_SYMBLOLIC_NAME_PREFIX_SIZE;

		ntStatus = GetFileHandle( &hFile, &__ShortPathName );
		if( !NT_SUCCESS( ntStatus ) )
		{
			goto RETURN_ERROR;
		}

		RtlCopyMemory( __FullPathName.Buffer, ShortPathName->Buffer, FILE_SYMBLOLIC_NAME_PREFIX_SIZE );

		__FullPathName.Length = FILE_SYMBLOLIC_NAME_PREFIX_SIZE;
		pwszAfterSymPrefix = ShortPathName->Buffer + FILE_SYMBLOLIC_NAME_PREFIX_SIZE / sizeof( WCHAR );

		bPathEnd = FALSE;
		dwWritedLength = FILE_SYMBLOLIC_NAME_PREFIX_SIZE;

		for( ; ; )
		{
			if( ShortPathName->Length <= dwWritedLength )
			{
				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				goto OUTPUT_FULL_PATH;
			}

			pwszPathDelim = FindWideCharInWideString( pwszAfterSymPrefix, 
				( ShortPathName->Length - dwWritedLength ) / sizeof( WCHAR ), 
				 PATH_DELIM 
				);

			if( NULL == pwszPathDelim )
			{
				pwszPathDelim = ShortPathName->Buffer + ShortPathName->Length;
			}

			if( pwszPathDelim == ShortPathName->Buffer + ShortPathName->Length )
			{
				bPathEnd = TRUE;
			}

			ntStatus = QueryFileAndDirInfo( hFile, pwszAfterSymPrefix, pwszPathDelim, pFileInfo, COMMON_OBJ_NAME_MAX_LENGTH );

			if( !NT_SUCCESS( ntStatus ) )
			{
				goto RETURN_ERROR;
			}

			dwFileNameLength = pFileInfo->FileNameLength + ( DWORD )__FullPathName.Length + sizeof( WCHAR );

			if( dwFileNameLength > __FullPathName.MaximumLength )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				goto RETURN_ERROR;
			}

			dwFileNameLength = __FullPathName.Length / sizeof( WCHAR );
			if( __FullPathName.Buffer[ __FullPathName.Length / sizeof( WCHAR ) - 1 ] != L'\\' )
			{
				__FullPathName.Buffer[ __FullPathName.Length / sizeof( WCHAR ) ] = L'\\';
				__FullPathName.Length += sizeof( WCHAR );
			}

			RtlCopyMemory( __FullPathName.Buffer + __FullPathName.Length, pFileInfo->FileName, pFileInfo->FileNameLength );
			__FullPathName.Length += ( USHORT )pFileInfo->FileNameLength;

			ZwClose( hFile );
			hFile = NULL;

			if( TRUE == bPathEnd )
			{
				goto OUTPUT_FULL_PATH;
			}

			__ShortPathName.MaximumLength = __ShortPathName.Length = ( PBYTE )pwszPathDelim - ( PBYTE )ShortPathName->Buffer;

			ntStatus = GetFileHandle( &hFile, &__ShortPathName );

			if( !NT_SUCCESS( ntStatus ) )
			{
				goto RETURN_ERROR;
			}

			dwWritedLength += ( pwszPathDelim - pwszAfterSymPrefix + 1 ) * sizeof( WCHAR );

			pwszAfterSymPrefix = pwszPathDelim + 1;

			if( pwszAfterSymPrefix < ShortPathName->Buffer + ShortPathName->Length  )
			{
				continue;
			}

			ntStatus = STATUS_INVALID_PARAMETER;
			goto RETURN_ERROR;
		}

OUTPUT_FULL_PATH:
		FullPathName->Length = __FullPathName.Length;
		FullPathName->MaximumLength = __FullPathName.MaximumLength;

		FullPathName->Buffer = AllocZeroPoolWithTag( NonPagedPool, __FullPathName.Length );

		if( NULL == FullPathName->Buffer )
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			goto RETURN_ERROR;
		}

		RtlCopyMemory( FullPathName->Buffer, __FullPathName.Buffer, __FullPathName.Length );
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}

RETURN_ERROR:
	if( NULL != __FullPathName.Buffer )
	{
		ExFreePoolWithTag( __FullPathName.Buffer, 0 );
	}

	if( NULL != pFileInfo )
	{
		ExFreePoolWithTag( pFileInfo, 0 );
	}

	if( NULL != hFile )
	{
		ZwClose( hFile );
	}

	return ntStatus;
}

NTSTATUS  GetProcessImagePath( DWORD dwProcessId, PUNICODE_STRING ProcessImageFilePath, DWORD dwBufferLen )
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	POBJECT_NAME_INFORMATION pFileDosDeviceName;
	ULONG ImageFilePathLength;
	PFILE_OBJECT pFileDirectObject;
	PFILE_OBJECT pFileIndirectObject;
	HANDLE hFileDirect;
	HANDLE hFileIndirect;
	HANDLE hProcess;
	PEPROCESS pEProcess;
	NTSTATUS ntStatus;
	BOOL bFullPath;
	UNICODE_STRING FullPathName = { 0 };
	UNICODE_STRING FileDosName = { 0 };

	pEProcess = NULL;
	hProcess = NULL;
	hFileDirect = NULL;
	hFileIndirect = NULL;
	pFileDirectObject = NULL;
	pFileIndirectObject = NULL;
	bFullPath = FALSE;
	pFileDosDeviceName = NULL;

	//_try
	//{
		ntStatus = PsLookupProcessByProcessId( ( HANDLE )dwProcessId, &pEProcess );
		if( !NT_SUCCESS( ntStatus ) )
		{
			goto RETURN_ERROR;
		}

		ntStatus = ObOpenObjectByPointer( 
			pEProcess, 
			OBJ_KERNEL_HANDLE, 
			NULL, 
			FILE_ALL_ACCESS, 
			NULL, 
			KernelMode, 
			&hProcess 
			);

		if( !NT_SUCCESS( ntStatus ) )
		{
			goto RETURN_ERROR;
		}

		ntStatus = ZwQueryInformationProcess(
			hProcess,
			ProcessImageFileName,
			ProcessImageFilePath,
			dwBufferLen,
			&ImageFilePathLength 
			);

		if( !NT_SUCCESS( ntStatus ) )
		{
			goto RETURN_ERROR;
		}

		InitializeObjectAttributes( 
			&ObjectAttributes, 
			ProcessImageFilePath, 
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL, 
			NULL 
			);

		ntStatus = ZwOpenFile(
			&hFileDirect,
			GENERIC_READ,
			&ObjectAttributes,
			&IoStatusBlock,
			FILE_SHARE_READ,
			FILE_SYNCHRONOUS_IO_NONALERT 
			); //First get process image file path by its process handle

		if( NT_SUCCESS( ntStatus ) )
		{
			if ( NULL != FindWideCharInWideString( 
				ProcessImageFilePath->Buffer,
				ProcessImageFilePath->Length / sizeof( WCHAR ),
				SHORT_PATH_SIGN 
				) )
			{
				bFullPath = TRUE;
				FileDosName.MaximumLength = COMMON_OBJ_NAME_MAX_LENGTH;
				FileDosName.Buffer = AllocZeroPoolWithTag( NonPagedPool, COMMON_OBJ_NAME_MAX_LENGTH );

				if ( NULL == FileDosName.Buffer )
				{
					ntStatus= STATUS_INSUFFICIENT_RESOURCES;
					goto RETURN_ERROR;
				}

				RtlCopyMemory( FileDosName.Buffer, DOS_DEVICE_NAME_PREFIX, CONST_STRING_SIZE( DOS_DEVICE_NAME_PREFIX ) );

				FileDosName.Length = CONST_STRING_SIZE( DOS_DEVICE_NAME_PREFIX );

				ntStatus = ObReferenceObjectByHandle( 
					hFileDirect, 
					0, 
					*IoFileObjectType, 
					0, 
					&pFileDirectObject, 
					0
					);

				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				ntStatus = IoQueryFileDosDeviceName( pFileDirectObject, &pFileDosDeviceName );
				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				ASSERT( NULL != pFileDosDeviceName && NULL != pFileDosDeviceName->Name.Buffer );
				if( FileDosName.MaximumLength < FileDosName.Length + pFileDosDeviceName->Name.Length )
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					goto RETURN_ERROR;
				}

				RtlCopyMemory( 
					( FileDosName.Buffer + FileDosName.Length ), 
					pFileDosDeviceName->Name.Buffer, 
					pFileDosDeviceName->Name.Length 
					);

				FileDosName.Length += pFileDosDeviceName->Name.Length;

				ntStatus = ShortPathNameToEntirePathName( &FileDosName, &FullPathName );
				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				InitializeObjectAttributes( 
					&ObjectAttributes, 
					&FullPathName,
					OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
					NULL,
					NULL
					);

				ntStatus = ZwCreateFile(
					&hFileIndirect,
					GENERIC_READ,
					&ObjectAttributes,
					&IoStatusBlock,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT,
					NULL,
					0
					);

				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				ntStatus = ObReferenceObjectByHandle(
					hFileIndirect,
					0,
					*IoFileObjectType,
					KernelMode,
					&pFileIndirectObject,
					NULL
					);

				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				ntStatus = ObQueryNameString( 
					pFileIndirectObject, 
					( POBJECT_NAME_INFORMATION )ProcessImageFilePath, 
					dwBufferLen, 
					&ImageFilePathLength
					);
			}
		}
		else
		{
			FileDosName.MaximumLength = COMMON_OBJ_NAME_MAX_LENGTH;
			FileDosName.Buffer = AllocZeroPoolWithTag( NonPagedPool, COMMON_OBJ_NAME_MAX_LENGTH );

			if ( NULL == FileDosName.Buffer )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				goto RETURN_ERROR;
			}

			RtlCopyMemory( FileDosName.Buffer, DOS_DEVICE_NAME_PREFIX, CONST_STRING_SIZE( DOS_DEVICE_NAME_PREFIX ) );
			FileDosName.Length = CONST_STRING_SIZE( DOS_DEVICE_NAME_PREFIX );

			ntStatus = EnterUserProcessReadImagePath( pEProcess, &FileDosName );
			if( !NT_SUCCESS( ntStatus ) )
			{
				goto RETURN_ERROR;
			}

			if( NULL == FindWideCharInWideString(
				( LPCWSTR )FileDosName.Buffer,
				FileDosName.Length / sizeof( WCHAR ), 
				SHORT_PATH_SIGN
				) )
			{
				InitializeObjectAttributes( 
					&ObjectAttributes, 
					&FileDosName, 
					OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
					NULL, 
					NULL
					);

				ntStatus= ZwCreateFile(
					&hFileIndirect,
					GENERIC_READ,
					&ObjectAttributes,
					&IoStatusBlock,
					0,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT,
					NULL,
					0 );

				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				ntStatus = ObReferenceObjectByHandle(
					hFileIndirect, 
					0,
					*IoFileObjectType,
					KernelMode,
					&pFileIndirectObject,
					NULL
					);

				if( !NT_SUCCESS( ntStatus ) )
				{
					goto RETURN_ERROR;
				}

				ntStatus = ObQueryNameString( 
					pFileIndirectObject, 
					( POBJECT_NAME_INFORMATION )ProcessImageFilePath, 
					dwBufferLen, 
					&ImageFilePathLength
					);
			}
		}

		//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	ntStatus = GetExceptionCode();
	//}

RETURN_ERROR:
	if( NULL != pEProcess )
	{
		ObfDereferenceObject( pEProcess );
	}

	if( NULL != hProcess )
	{
		ZwClose( hProcess );
	}

	if( NULL != pFileDosDeviceName )
	{
		ExFreePool( pFileDosDeviceName );
	}

	if( NULL != pFileIndirectObject )
	{
		ObfDereferenceObject( pFileIndirectObject );
	}

	if( NULL != hFileIndirect )
	{
		ZwClose( hFileIndirect );
	}

	if( NULL != pFileDirectObject )
	{
		ObfDereferenceObject( pFileDirectObject );
	}

	if( NULL != hFileDirect )
	{
		ZwClose( hFileDirect );
	}

	if( NULL != FileDosName.Buffer )
	{
		ExFreePoolWithTag( FileDosName.Buffer, 0 );
	}

	return ntStatus;
}

NTSTATUS RegisterProcessCreateNotify()
{
	NTSTATUS ntStatus;

	ntStatus = PsSetCreateProcessNotifyRoutine( ( PCREATE_PROCESS_NOTIFY_ROUTINE )DeleteProcessIoInfo, FALSE );
	return ntStatus;
}

NTSTATUS DeregisterProcessCreateNotify()
{
	NTSTATUS ntStatus;
	ntStatus = PsSetCreateProcessNotifyRoutine( ( PCREATE_PROCESS_NOTIFY_ROUTINE )DeleteProcessIoInfo, TRUE );
	return ntStatus;
}
