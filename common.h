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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <ntifs.h>

#define TDI_FILTER_POOL_TAG 0x74303633

PVOID  AllocZeroPoolWithTag( POOL_TYPE Type, size_t Size );

__inline VOID INTERLOCKED_COMPARE_EXCHANGE64( LARGE_INTEGER *pOriginalValue, LARGE_INTEGER NewValue )
{
	LARGE_INTEGER OriginalValue;

	ASSERT( NULL != pOriginalValue );
	
	__asm
	{
ATOM_CMPXCHG:
		mov esi, dword ptr [ pOriginalValue ];
		mov ebx, dword ptr [ esi ];
		mov ecx, dword ptr [ esi + 4 ];

		mov dword ptr [ OriginalValue ], ebx;
		mov dword ptr [ OriginalValue + 4 ], ecx;

		mov eax, ebx;
		mov edx, ecx;

		mov ebx, dword ptr [ NewValue ];
		mov ecx, dword ptr [ NewValue + 4 ];

		mov edi, esi;

		lock cmpxchg8b [ edi ];

		cmp eax, dword ptr [ OriginalValue ];
		jnz ATOM_CMPXCHG;

		cmp edx, dword ptr [ OriginalValue + 4 ];
		jnz ATOM_CMPXCHG;
	}
	return;
}

__inline VOID INTERLOCKED_HALF_COMPARE_EXCHANGE_ADD64( LARGE_INTEGER *pOriginalValue, LARGE_INTEGER AddValue )
{
	LARGE_INTEGER OriginalValue;

	ASSERT( NULL != pOriginalValue );
	
	__asm
	{
ATOM_CMPXCHG:
		mov esi, dword ptr [ pOriginalValue ];
		mov ebx, dword ptr [ esi ];
		mov ecx, dword ptr [ esi + 4 ];

		mov dword ptr [ OriginalValue ], ebx;
		mov dword ptr [ OriginalValue + 4 ], ecx;

		mov eax, ebx;
		mov edx, ecx;

		add ebx, dword ptr [ AddValue ];
		adc ecx, dword ptr [ AddValue + 4 ];

		mov edi, esi;

		lock cmpxchg8b [ edi ];

		cmp edx, dword ptr [ OriginalValue + 4 ];
		jnz ATOM_CMPXCHG;
	}
	return;
}

__inline VOID INTERLOCKED_COMPARE_EXCHANGE_ADD64( LARGE_INTEGER *pOriginalValue, LARGE_INTEGER AddValue )
{
	LARGE_INTEGER OriginalValue;

	ASSERT( NULL != pOriginalValue );
	
	__asm
	{
ATOM_CMPXCHG:
		mov esi, dword ptr [ pOriginalValue ];
		mov ebx, dword ptr [ esi ];
		mov ecx, dword ptr [ esi + 4 ];

		mov dword ptr [ OriginalValue ], ebx;
		mov dword ptr [ OriginalValue + 4 ], ecx;

		mov eax, ebx;
		mov edx, ecx;

		add ebx, dword ptr [ AddValue ];
		adc ecx, dword ptr [ AddValue + 4 ];

		mov edi, esi;

		lock cmpxchg8b [ edi ];

		cmp eax, dword ptr [ OriginalValue ];
		jnz ATOM_CMPXCHG;

		cmp edx, dword ptr [ OriginalValue + 4 ];
		jnz ATOM_CMPXCHG;
	}
	return;
}

#endif