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

#include "common.h"

PVOID AllocZeroPoolWithTag( POOL_TYPE Type, size_t Size )
{
	PVOID pPool;

	pPool = ExAllocatePoolWithTag( Type, Size, TDI_FILTER_POOL_TAG );
	
	if( pPool )
		RtlZeroMemory( pPool, Size );

	return pPool;
}
