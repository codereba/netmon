/*
 * Copyright 2010 JiJie.Shi.
 *
 * This file is part of netmon.
 * Licensed under the Gangoo License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ___NETMON_GLOBAL_H__
#define ___NETMON_GLOBAL_H__

// The pplication to call this driver
#define IO_SENDING_SIZE_INIT_VALUE_LOW 0xFFFFFFFF
#define IO_SENDING_SIZE_INIT_VALUE_HIGH 0x7FFFFFFF
#define PROCESS_NETWORK_TRAFFIC_INIT_REFERRENCE 2
#define COMMON_OBJ_NAME_MAX_LENGTH 0x400
#define TDI_EVENT_CONTEXT_MARK 0xFEC02B00
#define TDI_FILTER_LOOKASIDE_POOL_TAG 'vect'
#define TDI_FILTER_TIMER_ELAPSE_TIME -10000000 //1 second
#define WAIT_CONFIGURED_PROC_TIME -100000 //10 milli second
#define SHORT_PATH_SIGN L'~'
#define PATH_DELIM L'\\'
#define CONST_STRING_SIZE( const_str ) ( DWORD )( sizeof( const_str ) - sizeof( const_str[ 0 ] ) )
#define FILE_SYMBLOLIC_NAME_PREFIX L"\\??\\\\:\\"
#define FILE_SYMBLOLIC_NAME_PREFIX_SIZE CONST_STRING_SIZE( FILE_SYMBLOLIC_NAME_PREFIX )

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

typedef struct __PROCESS_INFORMATION_RECORD
{
	WCHAR szNativeImageFileName[ PROCESS_IMAGE_FILE_PATH_INFO_MAX_LENGTH ];
	WCHAR szImageFileName[ MAX_PATH ];
	BOOL bRemove;
	BOOL bStopSend;
	BOOL bStopRecv;
	LARGE_INTEGER SendingSpeed;
} PROCESS_INFORMATION_RECORD, *PPROCESS_INFORMATION_RECORD;

#endif //___NETMON_GLOBAL_H__