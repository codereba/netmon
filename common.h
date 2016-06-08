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