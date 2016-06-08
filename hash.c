/*
 * Copyright 2010 JiJie Shi
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
#include "netmon_.h"
#include "hash.h"

dword modulo_hash( hash_key key, dword table_size )
{
	ASSERT( 0 < table_size );

	return key.low_part % table_size;
}

int hash_item_is_empty( hash_item *item )
{
	return ( 0 == item->key.high_part && 0 == item->key.low_part );
}

#define compare_key( key1, key2 ) ( key1.high_part == key2.high_part && key1.low_part == key2.low_part )

int find_item_in_list( hash_item *list, hash_key key, hash_item **prev_item, hash_item **item )
{
	hash_item *__prev_item;
	hash_item *locate_item;

	ASSERT( NULL != item );

	__prev_item = NULL;
	locate_item = list;

	for( ; ; )
	{
		if( NULL == locate_item )
		{
			break;
		}
		
		if( compare_key( locate_item->key, key ) )
		{
			if( NULL != prev_item )
				*prev_item = __prev_item;
			
			if( NULL != item )
				*item = locate_item;
			
			return 0;
		}

		__prev_item = locate_item;
		locate_item = locate_item->next_link;
	}

	if( NULL != prev_item )
		*prev_item = NULL;

	if( NULL != item )
		*item = NULL;
	return -1; 
}

int locate_hash_item( hash_table *table, hash_key key, hash_item **item )
{
	dword index;
	hash_item *finded_item;

	ASSERT( NULL != table );
	ASSERT( NULL != item );

	index = modulo_hash( key, table->size );

	finded_item = &table->items[ index ];

	if( FALSE == hash_item_is_empty( finded_item ) )
	{
		*item = NULL;
		return -1;
	}
	
	if( TRUE == compare_key( finded_item->key, key ) )
	{
		*item = finded_item;
		return 0;
	}

	if( NULL == finded_item->next_link )
	{
		*item = NULL;
		return -1;
	}

	return find_item_in_list( finded_item->next_link, key, NULL, item );
}

int add_hash_item( hash_table *table, hash_key key, hash_value val )
{
	int ret;
	dword index;
	hash_item *item;
	hash_item *new_item;
	
	ASSERT( NULL != table );

	index = modulo_hash( key, table->size );

	item = &table->items[ index ];

	if( hash_item_is_empty( item ) )
	{
		item->key = key;
		item->value = val;
		item->next_item = table->first_hash_item;
		item->next_link = NULL;
		table->first_hash_item = item;
		table->item_count += 1;
		DebugPrintEx( IRP_CANCEL_INFO, "hash table item count is %d key is 0x%0.8x\n", 
			table->item_count, 
			key.low_part );
		return 0;
	}
	else
	{
		if( TRUE == compare_key( item->key, key ) )
		{
			return HASH_KEY_EXISTED;
		}
	}

	if( NULL != item->next_link )
	{
		ret = find_item_in_list( item->next_link, key, NULL, NULL );
		if( 0 == ret )
		{
			return HASH_KEY_EXISTED;
		}
	}

	new_item = ( hash_item* )AllocZeroPoolWithTag( NonPagedPool, sizeof( hash_item ) );
	if( NULL == new_item )
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	new_item->key = key;
	new_item->value = val;
	new_item->next_item = item->next_item;
	new_item->next_link = item->next_link;
	item->next_link = new_item;
	table->item_count += 1;
	DebugPrintEx( IRP_CANCEL_INFO, "hash table item count is %d key is 0x%0.8x\n", 
		table->item_count, 
		key.low_part );

	return 0;
}

hash_item *find_prev_item( hash_table *table, hash_item *item )
{
	hash_item *finded_item;

	ASSERT( NULL != table );
	ASSERT( NULL != item );
	ASSERT( NULL != table->header );

	finded_item = table->header;
	for( ; ; )
	{
		if( finded_item == NULL )
		{
			ASSERT( FALSE );
			return NULL;
		}

		if( finded_item->next_item == item )
		{
			return finded_item;
		}

		finded_item = finded_item->next_item;
	}
	return NULL;
}

int del_hash_item( hash_table *table, hash_key key, hash_value *value )
{
	int ret;
	dword index;
	hash_item *item;
	hash_item *finded_item;
	hash_item *prev_item;

	ASSERT( NULL != table );

	index = modulo_hash( key, table->size );
	
	item = &table->items[ index ];

	if( NULL != value )
	{
		*value = NULL;
	}

	if( compare_key( item->key, key ) )
	{
		prev_item = find_prev_item( table, item );

		if( NULL == prev_item )
		{
			ASSERT( FALSE );
			return -1;
		}
		
		prev_item->next_item = item->next_item;

		table->item_count -= 1;
		DebugPrintEx( IRP_CANCEL_INFO, "hash table item count is %d key is 0x%0.8x\n", 
			table->item_count, 
			key.low_part );
		item->key.high_part = 0;
		item->key.low_part = 0;
		item->next_item = NULL;
		if( NULL != value )
		{
			*value = item->value;
		}	
		item->value = 0;

		return 0;
	}

	if( NULL == item->next_link )
	{
		return -1;
	}

	ret = find_item_in_list( item->next_link, key, &prev_item, &finded_item );
	if( 0 > ret )
	{
		return ret;
	}

	if( NULL != prev_item )
	{
		prev_item->next_link = finded_item->next_link;
	}

	table->item_count -= 1;
	DebugPrintEx( IRP_CANCEL_INFO, "hash table item count is %d key is 0x%0.8x\n", 
		table->item_count, 
		key.low_part );

	if( NULL != value )
	{
		*value = finded_item->value;
	}
	ExFreePoolWithTag( finded_item, 0 );

	return 0;
}

int get_hash_value( hash_table *table, hash_key key, hash_value *value )
{
	int ret;
	hash_item *item;

	ret = locate_hash_item( table, key, &item );
	
	if( 0 > ret )
	{
		*value = NULL;
		return ret;
	}

	*value = item->value;

	return 0;
}

int init_hash_table( hash_table *table, dword size )
{
#define ADD_HEADER_SIZE( size ) ( size + 1 )
	hash_item *__header;
	ASSERT( NULL != table );

	__header = ( hash_item* )AllocZeroPoolWithTag( NonPagedPool, sizeof( hash_item ) * ADD_HEADER_SIZE( size ) );

	if( NULL == __header )
	{
		table->header = NULL;
		table->items = NULL;
		table->size = 0;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	memset( __header, 0, sizeof( hash_item ) *  ADD_HEADER_SIZE( size ) );

	table->header = __header;
	table->items = &__header[ 1 ];
	table->size = size;
	table->item_count = 0;
	return 0;
}

hash_item* get_next_hash_item( hash_item *item )
{
	ASSERT( NULL != item );
	if( NULL != item->next_link )
	{
		return item->next_link;
	}

	return item->next_item;
}

void destroy_hash_table( hash_table *table, destroy_hash_value des_func, dword param )
{
	hash_item *item_list;
	hash_item *item;
	//hash_item *next_item;
	hash_item *next_list;

	ASSERT( NULL != table );

	item = table->header->next_item;

	for( ; ; )
	{
		if( NULL == item )
			break;

		if( FALSE == hash_item_is_empty( item ) )
		{
			if( NULL != des_func )
			{
				des_func( item->value, param );
			}
		}

		item_list = item->next_link;

		for( ; ; )
		{
			if( NULL == item_list )
			{
				break;
			}

			next_list = item_list->next_link;

			if( NULL != des_func )
			{
				des_func( item_list->value, param );
			}

			ExFreePoolWithTag( item_list, 0 );
			item_list = next_list;
		}

		item = item->next_item;
	}

	ExFreePoolWithTag( table->header, 0 );
}


uint64 make_hash_key( dword higher, dword lower )
{
	hash_key key;
	key.high_part = higher;
	key.low_part = lower;
	return key.quad_part;
}

void* get_next_item_value( void *pos_record, hash_table *table, hash_value *value )
{
	hash_item *item;

	ASSERT( NULL != table );

	if( NULL == pos_record )
	{
		item = table->first_hash_item;
	}
	else
	{
		item = ( hash_item* )pos_record;
		item = get_next_hash_item( item );
	}

	if( NULL == item )
	{
		*value = HASH_NULL_VALUE;
		return NULL;
	}

	*value = item->value;
	return ( void* )item;
}

int hash_is_empty( hash_table *table )
{
	if( NULL == table->header->next_item )
	{
		return 0;
	}

	return -1;
}