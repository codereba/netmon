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

#include "common.h"

PVOID AllocZeroPoolWithTag( POOL_TYPE Type, size_t Size )
{
	PVOID pPool;

	pPool = ExAllocatePoolWithTag( Type, Size, TDI_FILTER_POOL_TAG );
	
	if( pPool )
		RtlZeroMemory( pPool, Size );

	return pPool;
}
