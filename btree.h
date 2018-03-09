#ifndef STRACE_BTREE_H
#define STRACE_BTREE_H

/* Simple B-tree interface */

#define BTREE_SET   ((uint64_t **) ~(intptr_t) 0)
#define BTREE_UNSET ((uint64_t **) NULL)

#define PTR_BLOCK_SIZE_LG_MAX   18
#define DATA_BLOCK_SIZE_LG_MAX  20

enum btree_iterate_flags {
	BTREE_ITERATE_KEYS_SET   = 1 << 0,
	BTREE_ITERATE_KEYS_UNSET = 1 << 1,
};

/**
 * B-tree control structure.
 * B-tree implemented here has the following properties:
 *  * It allows storing values of the same size, the size can vary from 1 bit to
 *    64 bit values (only power of 2 sizes are allowed).
 *  * The key can be up to 64 bits in size.
 *  * It has separate configuration for pointer block size and data block size.
 *  * It can be used for mask storage - supports storing the flag that all keys
 *    are set/unset in the middle tree layers. See also btree_mask_set() and
 *    btree_mask_unset().
 *
 * How bits of key are used for different block levels:
 *
 *     highest bits                                         lowest bits
 *     | ptr_block_size_lg | ... | < remainder > | data_block_size_lg |
 *     \______________________________________________________________/
 *                                 key_size
 *
 * So, the remainder is used on the lowest non-data node level.
 *
 * As of now, it doesn't implement any mechanisms for resizing/changing key
 * size.  De-fragmentation is also unsupported currently.
 */
struct btree {
	uint64_t set_value;         /**< Default set value */
	uint64_t **data;
	uint8_t item_size_lg;       /**< Item size log2, in bits, 0..6. */
	/** Pointer block size log2, in pointers sizes. 8-14, usually. */
	uint8_t ptr_block_size_lg;
	/** Data block size log2, in bytes. 8-14, usually. */
	uint8_t data_block_size_lg;
	uint8_t key_size;           /**< Key size, in bits, 1..64. */
};


bool btree_check(uint8_t item_size_lg, uint8_t ptr_block_size_lg,
		 uint8_t data_block_size_lg, uint8_t key_size);
void btree_init(struct btree *b, uint8_t item_size_lg,
		uint8_t ptr_block_size_lg, uint8_t data_block_size_lg,
		uint8_t key_size, uint64_t set_value);
struct btree * btree_create(uint8_t item_size_lg, uint8_t ptr_block_size_lg,
			    uint8_t data_block_size_lg, uint8_t key_size,
			    uint64_t set_value);

bool btree_set(struct btree *b, uint64_t key, uint64_t val);
#if 0
/**
 * Sets to the value b->set_value all keys with 0-ed bits of mask equivalent to
 * corresponding bits in key.
 */
int btree_mask_set(struct btree *b, uint64_t key, uint8_t mask_bits);
/**
 * Sets to 0 all keys with 0-ed bits of mask equivalent to corresponding bits in
 * key.
 */
int btree_mask_unset(struct btree *b, uint64_t key, uint8_t mask_bits);
int btree_interval_set(struct btree *b, uint64_t begin, uint64_t end,
		       uint64_t val);

uint64_t btree_get_next_set_key(struct btree *b, uint64_t key);
uint64_t btree_iterate_keys(struct btree *b, uint64_t start, uint64_t end,
			    enum btree_iterate_flags flags, btree_iterate_fn fn,
			    void *fn_data);
#endif


uint64_t btree_get(struct btree *b, uint64_t key);

void btree_free_block(struct btree *b, uint64_t **block, uint8_t depth,
		      int max_depth);
void btree_free(struct btree *b);

#endif /* !STRACE_BTREE_H */
