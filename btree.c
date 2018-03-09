/* Simple B-tree implementation for key-value mapping storage */

#include "defs.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "btree.h"

static const ptr_sz_lg = (sizeof(uint64_t *) == 8 ? 3 : 2);

bool
btree_check(uint8_t item_size_lg, uint8_t ptr_block_size_lg,
	    uint8_t data_block_size_lg, uint8_t key_size)
{
	if (item_size_lg > 6)
		return false;
	if (key_size < 1 || key_size > 64)
		return false;
	if (ptr_block_size_lg < 1 || ptr_block_size_lg > PTR_BLOCK_SIZE_LG_MAX)
		return false;
	if (data_block_size_lg > DATA_BLOCK_SIZE_LG_MAX ||
	    data_block_size_lg < 3 ||
	    item_size_lg > (data_block_size_lg + 3))
		return false;

	return true;
}

void
btree_init(struct btree *b, uint8_t item_size_lg, uint8_t ptr_block_size_lg,
	   uint8_t data_block_size_lg, uint8_t key_size, uint64_t set_value)
{
	assert(btree_check(item_size_lg, ptr_block_size_lg, data_block_size_lg,
			   key_size));

	b->set_value = set_value;
	b->data = BTREE_UNSET;
	b->item_size_lg = item_size_lg;
	b->ptr_block_size_lg = ptr_block_size_lg;
	b->data_block_size_lg = data_block_size_lg;
	b->key_size = key_size;
}

static uint8_t
btree_get_depth(struct btree *b)
{
	return (b->key_size - (b->data_block_size_lg + 3 - b->item_size_lg) +
		b->ptr_block_size_lg - 1) / b->ptr_block_size_lg;
}

/**
 * Returns lg2 of block size for the specific level of B-tree. If max_depth
 * provided is less than zero, it is calculated via btree_get_depth call.
 */
static uint8_t
btree_get_block_size(struct btree *b, uint8_t depth, uint8_t max_depth)
{
	if (!max_depth)
		max_depth = btree_get_depth(b);

	/* Last level contains data and we allow it having a different size */
	if (depth == max_depth)
		return b->data_block_size_lg;
	/* Last level of the tree can be smaller */
	if (depth == max_depth - 1)
		return (b->key_size -
			(b->data_block_size_lg + 3 - b->item_size_lg) +
			b->ptr_block_size_lg - 1) %
			b->ptr_block_size_lg + 1 + ptr_sz_lg;

	return b->ptr_block_size_lg + ptr_sz_lg;
}

#define round_down(a, b) (((a) / (b)) * (b))

/**
 * Provides starting offset of bits in key corresponding to the block index
 * at the specific level.
 */
static uint8_t
btree_get_block_bit_offs(struct btree *b, uint8_t depth, int max_depth)
{
	uint8_t offs;

	if (max_depth < 0)
		max_depth = btree_get_depth(b);

	if (depth == max_depth)
		return 0;

	offs = b->data_block_size_lg + 3 - b->item_size_lg;

	if (depth == max_depth - 1)
		return offs;

	/* data_block_size + remainder */
	offs = b->key_size - round_down(b->key_size - offs - 1,
		b->ptr_block_size_lg);

	return offs + (max_depth - depth - 2) * b->ptr_block_size_lg;
}

struct btree *
btree_create(uint8_t item_size_lg, uint8_t ptr_block_size_lg,
	     uint8_t data_block_size_lg, uint8_t key_size, uint64_t set_value)
{
	struct btree *b;

	if (!btree_check(item_size_lg, ptr_block_size_lg, data_block_size_lg,
	    key_size))
		return NULL;

	b = malloc(sizeof(*b));
	if (!b)
		return NULL;

	btree_init(b, item_size_lg, ptr_block_size_lg, data_block_size_lg,
		   key_size, set_value);

	return b;
}

static uint64_t
btree_filler(uint64_t val, uint8_t item_size)
{
	val &= (1 << (1 << item_size)) - 1;

	for (; item_size < 6; item_size++)
		val |= val << (1 << item_size);

	return val;
}

static uint64_t *
btree_get_block(struct btree *b, uint64_t key, bool auto_create)
{
	uint64_t ***cur_block = &(b->data);
	unsigned i;
	uint8_t cur_depth;
	uint8_t max_depth;
	uint8_t sz;

	if (b->key_size < 64 && key > (uint64_t) 1 << (1 << b->key_size))
		return NULL;

	max_depth = btree_get_depth(b);

	for (cur_depth = 0; cur_depth <= max_depth; cur_depth++) {
		sz = btree_get_block_size(b, cur_depth, max_depth);

		if (*cur_block == BTREE_SET || *cur_block == BTREE_UNSET) {
			uint64_t **old_val = *cur_block;

			if (!auto_create)
				return (uint64_t *) (*cur_block);

			*cur_block = xcalloc(1 << sz, 1);

			if (old_val == BTREE_SET) {
				uint64_t filler = (cur_depth == max_depth) ?
					btree_filler(b->set_value,
						     b->item_size_lg) :
					btree_filler((uintptr_t) BTREE_SET,
						     ptr_sz_lg + 3);

				for (i = 0; i < (1 << (sz - 3)); i++)
					((uint64_t *) *cur_block)[i] = filler;
			}
		}

		if (cur_depth < max_depth) {
			size_t pos = (key >> btree_get_block_bit_offs(b,
				cur_depth, max_depth)) & ((1 << (sz - ptr_sz_lg)) - 1);

			cur_block = (uint64_t ***) ((*cur_block) + pos);
		}
	}

	return (uint64_t *) (*cur_block);
}

bool
btree_set(struct btree *b, uint64_t key, uint64_t val)
{
	uint64_t *data = btree_get_block(b, key, true);
	size_t mask = (1 << (b->data_block_size_lg - 3)) - 1;
	size_t pos = (key & mask) >> (6 - b->item_size_lg);

	if (!data)
		return false;

	if (b->item_size_lg == 6) {
		data[pos] = val;
	} else {
		size_t offs = (key & ((1 << (6 - b->item_size_lg)) - 1)) <<
			b->item_size_lg;
		uint64_t mask =
			(uint64_t) ((1 << (1 << b->item_size_lg)) - 1) << offs;

		data[pos] &= ~mask;
		data[pos] |= (val << offs) & mask;
	}

	return true;
}

#if 0
int
btree_mask_set(struct btree *b, uint64_t key, uint8_t mask_bits)
{
}

/**
 * Sets to 0 all keys with 0-ed bits of mask equivalent to corresponding bits in
 * key.
 */
int
btree_mask_unset(struct btree *b, uint64_t key, uint8_t mask_bits)
{
}

int
btree_interval_set(struct btree *b, uint64_t begin, uint64_t end, uint64_t val)
{
}

uint64_t
btree_get_next_set_key(struct btree *b, uint64_t key)
{
}

uint64_t
btree_iterate_set_keys(struct btree *b, uint64_t start, uint64_t end,
		       btree_iterate_fn fn, void *fn_data)
{
}
#endif

uint64_t
btree_get(struct btree *b, uint64_t key)
{
	uint64_t *data = btree_get_block(b, key, false);
	size_t mask;
	size_t pos;
	size_t offs;

	if (!data)
		return 0;
	if ((void *) data == (void *) BTREE_SET)
		return b->set_value;

	mask = (1 << (b->data_block_size_lg - 3)) - 1;
	pos = (key & mask) >> (6 - b->item_size_lg);

	if (b->item_size_lg == 6)
		return data[pos];

	offs = (key & ((1 << (6 - b->item_size_lg)) - 1)) << b->item_size_lg;

	return (data[pos] >> offs) & ((1 << (1 << b->item_size_lg)) - 1);
}

void
btree_free_block(struct btree *b, uint64_t **block, uint8_t depth,
		 int max_depth)
{
	size_t count;
	size_t sz;
	size_t i;

	if (block == BTREE_SET || block == BTREE_UNSET)
		return;
	if (max_depth < 0)
		max_depth = btree_get_depth(b);
	if (depth >= max_depth)
		goto free_block;

	sz = 1 << (btree_get_block_size(b, depth, max_depth) - ptr_sz_lg);

	for (i = 0; i < sz; i++)
		if (((void *) block[i] != (void *) BTREE_SET) &&
		    ((void *) block[i] != (void *) BTREE_UNSET))
			btree_free_block(b, (uint64_t **) (block[i]), depth + 1,
					 max_depth);

free_block:
	free(block);
}

void
btree_free(struct btree *b)
{
	btree_free_block(b, b->data, 0, -1);
	free(b);
}
