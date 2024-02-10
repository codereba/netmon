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

#ifndef __BALANCE_PARALLEL_HASH_H__
#define __BALANCE_PARALLEL_HASH_H__

typedef unsigned __int64 uint64;
typedef unsigned long dword;
#define HASH_KEY_EXISTED -11
typedef struct __long_int
{
	union
	{
		struct 
		{
			dword low_part;
			dword high_part;
		};

		uint64 quad_part;
	};
} long_int;

typedef long_int hash_key;
typedef void *hash_value;
#define HASH_NULL_VALUE NULL
typedef struct __hash_item
{
	hash_key key;
	hash_value value;

	struct __hash_item *next_item;
	struct __hash_item *next_link;

} hash_item;

typedef struct __hash_table
{
#define first_hash_item header->next_item
	hash_item *header;
	hash_item *items;
	dword size;
	dword item_count;
} hash_table;

typedef int ( *hash_val_comp )( hash_val, hash_val );
typedef void ( *destroy_hash_value )( hash_value *value, dword param );

#define hash_table_inited( table ) ( NULL != ( table )->header )
#define compare_key( key1, key2 ) ( key1.high_part == key2.high_part && key1.low_part == key2.low_part )

dword modulo_hash( hash_key key, dword table_size );
int hash_item_is_empty( hash_item *item );
int find_item_in_list( hash_item *list, hash_key key, hash_item **prev_item, hash_item **item );
int locate_hash_item( hash_table *table, hash_key key, hash_item **item );
int add_hash_item( hash_table *table, hash_key key, hash_value val );
hash_item *find_prev_item( hash_table *table, hash_item *item );
int del_hash_item( hash_table *table, hash_key key, hash_value *value );
int get_hash_value( hash_table *table, hash_key key, hash_value *value );
int init_hash_table( hash_table *table, dword size );
hash_item* get_next_hash_item( hash_item *item );
void destroy_hash_table( hash_table *table, destroy_hash_value des_func, dword param );
uint64 make_hash_key( dword higher, dword lower );
void* get_next_item_value( void *pos_record, hash_table *table, hash_value *value );
int hash_is_empty( hash_table *table );

#endif //__BALANCE_PARALLEL_HASH_H__