/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/sched.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "duofs.h"
#include "xip.h"
#include "inode.h"

unsigned int blk_type_to_shift[DUOFS_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[DUOFS_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

int duofs_init_inode_inuse_list(struct super_block *sb)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct duofs_range_node *range_node;
	struct inode_map *inode_map;
	unsigned long range_high;
	int i;
	int ret;

	sbi->s_inodes_used_count = DUOFS_NORMAL_INODE_START;
	range_high = DUOFS_NORMAL_INODE_START / sbi->cpus;
	if (DUOFS_NORMAL_INODE_START % sbi->cpus)
		range_high++;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		range_node = duofs_alloc_inode_node(sb);
		if (range_node == NULL)
			/* FIXME: free allocated memories */
			return -ENOMEM;

		range_node->range_low = 0;
		range_node->range_high = range_high;
		ret = duofs_insert_inodetree(sbi, range_node, i);
		if (ret) {
			duofs_err(sb, "%s failed\n", __func__);
			duofs_free_inode_node(range_node);
			return ret;
		}
		inode_map->num_range_node_inode = 1;
		inode_map->first_inode_range = range_node;
	}

	return 0;
}

#define PAGES_PER_2MB 512

/*
 * allocate data blocks for inode and return the absolute blocknr.
 * Zero out the blocks if zero set. Increments inode->i_blocks
 */
static int duofs_new_data_blocks(struct super_block *sb, struct duofs_inode *pi,
				unsigned long* blocknr, unsigned int num,
				int zero, int cpu, int write_path)
{
	int allocated;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];

	duofs_dbg_verbose("%s: calling duofs_new_blocks with num = %u "
		 "data_bits = %u\n", __func__, num, data_bits);

	if (num == PAGES_PER_2MB && write_path == 0)
		pi->huge_aligned_file = 1;

	allocated = duofs_new_blocks(sb, blocknr, num,
				    pi->i_blk_type, zero,
				    cpu);

	if (allocated > 0) {
		duofs_memunlock_inode(sb, pi);
		le64_add_cpu(&pi->i_blocks,
			     (allocated << (data_bits - sb->s_blocksize_bits)));
		duofs_memunlock_inode(sb, pi);
	}

	return allocated;
}

/*
 * find the offset to the block represented by the given inode's file
 * relative block number.
 */
unsigned long duofs_find_data_blocks(struct inode *inode,
				    unsigned long file_blocknr,
				    u64 *bp,
				    unsigned long max_blocks)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	u32 blk_shift;
	unsigned long blk_offset, blocknr = file_blocknr;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;
	unsigned long num_blocks_found = 0;

	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - sb->s_blocksize_bits;
	blk_offset = file_blocknr & ((1 << blk_shift) - 1);
	blocknr = file_blocknr >> blk_shift;

	if (blocknr >= (1UL << (pi->height * meta_bits))) {
		*bp = 0;
		return 0;
	}

	num_blocks_found = __duofs_find_data_blocks(sb, pi, blocknr,
						   bp, max_blocks);
	duofs_dbg_verbose("find_data_block %lx, %x %llx blk_p %p blk_shift %x"
			 " blk_offset %lx\n", file_blocknr, pi->height, *bp,
			 duofs_get_block(sb, *bp), blk_shift, blk_offset);

	if (*bp == 0)
		return 0;

	*bp = *bp + (blk_offset << sb->s_blocksize_bits);
	return num_blocks_found;
}

/* recursive_find_region: recursively search the btree to find hole or data
 * in the specified range
 * Input:
 * block: points to the root of the b-tree
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */
static int recursive_find_region(struct super_block *sb, __le64 block,
	u32 height, unsigned long first_blocknr, unsigned long last_blocknr,
	int *data_found, int *hole_found, int hole)
{
	unsigned int meta_bits = META_BLK_SHIFT;
	__le64 *node;
	unsigned long first_blk, last_blk, node_bits, blocks = 0;
	unsigned int first_index, last_index, i;

	node_bits = (height - 1) * meta_bits;

	first_index = first_blocknr >> node_bits;
	last_index = last_blocknr >> node_bits;

	node = duofs_get_block(sb, le64_to_cpu(block));

	for (i = first_index; i <= last_index; i++) {
		if (height == 1 || node[i] == 0) {
			if (node[i]) {
				*data_found = 1;
				if (!hole)
					goto done;
			} else {
				*hole_found = 1;
			}

			if (!*hole_found || !hole)
				blocks += (1UL << node_bits);
		} else {
			first_blk = (i == first_index) ?  (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			blocks += recursive_find_region(sb, node[i], height - 1,
				first_blk, last_blk, data_found, hole_found,
				hole);
			if (!hole && *data_found)
				goto done;
			/* cond_resched(); */
		}
	}
done:
	return blocks;
}

/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
unsigned long duofs_find_region(struct inode *inode, loff_t *offset, int hole)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	unsigned long blocks = 0, offset_in_block;
	int data_found = 0, hole_found = 0;

	if (*offset >= inode->i_size)
		return -ENXIO;

	if (!inode->i_blocks || !pi->root) {
		if (hole)
			return inode->i_size;
		else
			return -ENXIO;
	}

	offset_in_block = *offset & ((1UL << data_bits) - 1);

	if (pi->height == 0) {
		data_found = 1;
		goto out;
	}

	first_blocknr = *offset >> data_bits;
	last_blocknr = inode->i_size >> data_bits;

	duofs_dbg_verbose("find_region offset %llx, first_blocknr %lx,"
		" last_blocknr %lx hole %d\n",
		  *offset, first_blocknr, last_blocknr, hole);

	blocks = recursive_find_region(inode->i_sb, pi->root, pi->height,
		first_blocknr, last_blocknr, &data_found, &hole_found, hole);

out:
	/* Searching data but only hole found till the end */
	if (!hole && !data_found && hole_found)
		return -ENXIO;

	if (data_found && !hole_found) {
		/* Searching data but we are already into them */
		if (hole)
			/* Searching hole but only data found, go to the end */
			*offset = inode->i_size;
		return 0;
	}

	/* Searching for hole, hole found and starting inside an hole */
	if (hole && hole_found && !blocks) {
		/* we found data after it */
		if (!data_found)
			/* last hole */
			*offset = inode->i_size;
		return 0;
	}

	if (offset_in_block) {
		blocks--;
		*offset += (blocks << data_bits) +
			   ((1 << data_bits) - offset_in_block);
	} else {
		*offset += blocks << data_bits;
	}

	return 0;
}

/* examine the meta-data block node up to the end_idx for any non-null
 * pointers. if found return false, else return true.
 * required to determine if a meta-data block contains no pointers and hence
 * can be freed.
 */
static inline bool is_empty_meta_block(__le64 *node, unsigned int start_idx,
	unsigned int end_idx)
{
	int i, last_idx = (1 << META_BLK_SHIFT) - 1;
	for (i = 0; i < start_idx; i++)
		if (unlikely(node[i]))
			return false;
	for (i = end_idx + 1; i <= last_idx; i++)
		if (unlikely(node[i]))
			return false;
	return true;
}

/* recursive_truncate_blocks: recursively deallocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * end: last byte offset of the range
 */
int truncate_strong_guarantees(struct super_block *sb, __le64 *node,
				      unsigned long num_blocks, u32 btype)
{
	unsigned long blocknr = 0;
	unsigned int node_bits, first_index, last_index, i;
	unsigned int freed = 0;
	unsigned long prev_blocknr = 0;
	int j;

	first_index = 0;
	last_index = num_blocks - 1;

	i = first_index;
	while (i <= last_index) {
		for (j = i; j <= last_index; j++) {
			prev_blocknr = blocknr;
			blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[j]), btype);

			if (blocknr != (prev_blocknr + 1) && prev_blocknr != 0) {
				blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[i]), btype);
				duofs_free_blocks(sb, blocknr, (j - i), btype);
				i = j;
				prev_blocknr = 0;
				blocknr = 0;
				break;
			}
		}
		if (j == last_index + 1) {
			if (i < j) {
				blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[i]), btype);
				duofs_free_blocks(sb, blocknr, (j - i), btype);
				i = j;
			}
		}
	}

	return num_blocks;
}

/* recursive_truncate_blocks: recursively deallocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * end: last byte offset of the range
 */
static int recursive_truncate_blocks(struct super_block *sb, __le64 block,
	u32 height, u32 btype, unsigned long first_blocknr,
	unsigned long last_blocknr, bool *meta_empty)
{
	unsigned long blocknr = 0, first_blk, last_blk;
	unsigned int node_bits, first_index, last_index, i;
	__le64 *node;
	unsigned int freed = 0, bzero;
	int start, end;
	bool mpty, all_range_freed = true;
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	unsigned long prev_blocknr = 0;
	int j;

	node = duofs_get_block(sb, le64_to_cpu(block));

	node_bits = (height - 1) * META_BLK_SHIFT;

	start = first_index = first_blocknr >> node_bits;
	end = last_index = last_blocknr >> node_bits;

	if (height == 1) {
		i = first_index;
		while (i <= last_index) {
			for (j = i; j <= last_index; j++) {
				if (unlikely(!node[j])) {
					if (i < j) {
						blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[i]), btype);
						duofs_free_blocks(sb, blocknr, (j - i), btype);
						freed += (j - i);
					}
					prev_blocknr = 0;
					blocknr = 0;
					i = j + 1;
					break;
				} else {
					prev_blocknr = blocknr;
					blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[j]), btype);
				}

				if (blocknr != (prev_blocknr + 1) && prev_blocknr != 0) {
					blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[i]), btype);
					duofs_free_blocks(sb, blocknr, (j - i), btype);
					freed += (j - i);
					i = j;
					prev_blocknr = 0;
					blocknr = 0;
					break;
				}
			}
			if (j == last_index + 1) {
				if (i < j) {
					blocknr = duofs_get_blocknr(sb, le64_to_cpu(node[i]), btype);
					duofs_free_blocks(sb, blocknr, (j - i), btype);
					freed += (j - i);
					i = j;
				}
			}
		}
	} else {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			freed += recursive_truncate_blocks(sb, node[i],
				height - 1, btype, first_blk, last_blk, &mpty);
			/* cond_resched(); */
			if (mpty) {
				/* Freeing the meta-data block */
				blocknr = duofs_get_blocknr(sb, le64_to_cpu(
					    node[i]), DUOFS_BLOCK_TYPE_4K);
				duofs_free_blocks(sb, blocknr, 1, DUOFS_BLOCK_TYPE_4K);
			} else {
				if (i == first_index)
				    start++;
				else if (i == last_index)
				    end--;
				all_range_freed = false;
			}
		}
	}
	if (all_range_freed &&
		is_empty_meta_block(node, first_index, last_index)) {
		*meta_empty = true;
	} else {
		/* Zero-out the freed range if the meta-block in not empty */
		if (start <= end) {
			bzero = (end - start + 1) * sizeof(u64);
			duofs_memunlock_block(sb, node);
			memset(&node[start], 0, bzero);
			duofs_memlock_block(sb, node);
			duofs_flush_buffer(&node[start], bzero, false);
		}
		*meta_empty = false;
	}
	return freed;
}

unsigned int duofs_free_inode_subtree(struct super_block *sb,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr)
{
	unsigned long first_blocknr;
	unsigned int freed;
	bool mpty;
	timing_t free_time;

	if (!root)
		return 0;

	DUOFS_START_TIMING(free_tree_t, free_time);
	if (height == 0) {
		first_blocknr = duofs_get_blocknr(sb, le64_to_cpu(root),
			btype);
		duofs_free_blocks(sb, first_blocknr, 1, btype);
		freed = 1;
	} else {
		first_blocknr = 0;

		freed = recursive_truncate_blocks(sb, root, height, btype,
			first_blocknr, last_blocknr, &mpty);
		BUG_ON(!mpty);
		first_blocknr = duofs_get_blocknr(sb, le64_to_cpu(root),
			DUOFS_BLOCK_TYPE_4K);
		duofs_free_blocks(sb, first_blocknr, 1, DUOFS_BLOCK_TYPE_4K);
	}
	DUOFS_END_TIMING(free_tree_t, free_time);
	return freed;
}

static void duofs_decrease_btree_height(struct super_block *sb,
	struct duofs_inode *pi, unsigned long newsize, __le64 newroot)
{
	unsigned int height = pi->height, new_height = 0;
	unsigned long blocknr, last_blocknr;
	__le64 *root;
	char b[8];

	if (pi->i_blocks == 0 || newsize == 0) {
		/* root must be NULL */
		BUG_ON(newroot != 0);
		goto update_root_and_height;
	}

	last_blocknr = ((newsize + duofs_inode_blk_size(pi) - 1) >>
		duofs_inode_blk_shift(pi)) - 1;
	while (last_blocknr > 0) {
		last_blocknr = last_blocknr >> META_BLK_SHIFT;
		new_height++;
	}
	if (height == new_height)
		return;
	duofs_dbg_verbose("reducing tree height %x->%x\n", height, new_height);
	while (height > new_height) {
		/* freeing the meta block */
		root = duofs_get_block(sb, le64_to_cpu(newroot));
		blocknr = duofs_get_blocknr(sb, le64_to_cpu(newroot),
			DUOFS_BLOCK_TYPE_4K);
		newroot = root[0];
		duofs_free_blocks(sb, blocknr, 1, DUOFS_BLOCK_TYPE_4K);
		height--;
	}
update_root_and_height:
	/* pi->height and pi->root need to be atomically updated. use
	 * cmpxchg16 here. The following is dependent on a specific layout of
	 * inode fields */
	*(u64 *)b = *(u64 *)pi;
	/* pi->height is at offset 2 from pi */
	b[2] = (u8)new_height;
	/* TODO: the following function assumes cmpxchg16b instruction writes
	 * 16 bytes atomically. Confirm if it is really true. */
	cmpxchg_double_local((u64 *)pi, &pi->root, *(u64 *)pi, pi->root,
		*(u64 *)b, newroot);
}

static unsigned long duofs_inode_count_iblocks_recursive(struct super_block *sb,
		__le64 block, u32 height)
{
	__le64 *node;
	unsigned int i;
	unsigned long i_blocks = 0;

	if (height == 0)
		return 1;
	node = duofs_get_block(sb, le64_to_cpu(block));
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		i_blocks += duofs_inode_count_iblocks_recursive(sb, node[i],
								height - 1);
	}
	return i_blocks;
}

static inline unsigned long duofs_inode_count_iblocks (struct super_block *sb,
	struct duofs_inode *pi, __le64 root)
{
	unsigned long iblocks;
	if (root == 0)
		return 0;
	iblocks = duofs_inode_count_iblocks_recursive(sb, root, pi->height);
	return (iblocks << (duofs_inode_blk_shift(pi) - sb->s_blocksize_bits));
}

/* Support for sparse files: even though pi->i_size may indicate a certain
 * last_blocknr, it may not be true for sparse files. Specifically, last_blocknr
 * can not be more than the maximum allowed by the inode's tree height.
 */
static inline unsigned long duofs_sparse_last_blocknr(unsigned int height,
		unsigned long last_blocknr)
{
	if (last_blocknr >= (1UL << (height * META_BLK_SHIFT)))
		last_blocknr = (1UL << (height * META_BLK_SHIFT)) - 1;
	return last_blocknr;
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void __duofs_truncate_blocks(struct inode *inode, loff_t start,
				    loff_t end)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	unsigned long first_blocknr, last_blocknr;
	__le64 root;
	unsigned int freed = 0;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;
	bool mpty;

	inode->i_mtime = inode->i_ctime = current_time(inode);

	if (!pi->root)
		goto end_truncate_blocks;

	duofs_dbg_verbose("truncate: pi %p iblocks %llx %llx %llx %x %llx\n", pi,
			 pi->i_blocks, start, end, pi->height, pi->i_size);

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (pi->i_flags & cpu_to_le32(DUOFS_EOFBLOCKS_FL)) {
		last_blocknr = (1UL << (pi->height * meta_bits)) - 1;
	} else {
		if (end == 0)
			goto end_truncate_blocks;
		last_blocknr = (end - 1) >> data_bits;
		last_blocknr = duofs_sparse_last_blocknr(pi->height,
			last_blocknr);
	}

	if (first_blocknr > last_blocknr)
		goto end_truncate_blocks;
	root = pi->root;

	if (pi->height == 0) {
		first_blocknr = duofs_get_blocknr(sb, le64_to_cpu(root),
			pi->i_blk_type);
		duofs_free_blocks(sb, first_blocknr, 1, pi->i_blk_type);
		root = 0;
		freed = 1;
	} else {
		freed = recursive_truncate_blocks(sb, root, pi->height,
			pi->i_blk_type, first_blocknr, last_blocknr, &mpty);
		if (mpty) {
			first_blocknr = duofs_get_blocknr(sb, le64_to_cpu(root),
				DUOFS_BLOCK_TYPE_4K);
			duofs_free_blocks(sb, first_blocknr, 1, DUOFS_BLOCK_TYPE_4K);
			root = 0;
		}
	}
	/* if we are called during mount, a power/system failure had happened.
	 * Don't trust inode->i_blocks; recalculate it by rescanning the inode
	 */
	if (duofs_is_mounting(sb))
		inode->i_blocks = duofs_inode_count_iblocks(sb, pi, root);
	else
		inode->i_blocks -= (freed * (1 << (data_bits -
				sb->s_blocksize_bits)));

	duofs_memunlock_inode(sb, pi);
	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	duofs_decrease_btree_height(sb, pi, start, root);
	/* Check for the flag EOFBLOCKS is still valid after the set size */
	check_eof_blocks(sb, pi, inode->i_size);
	duofs_memlock_inode(sb, pi);
	/* now flush the inode's first cacheline which was modified */
	duofs_flush_buffer(pi, 1, false);
	return;
end_truncate_blocks:
	/* we still need to update ctime and mtime */
	duofs_memunlock_inode(sb, pi);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	duofs_memlock_inode(sb, pi);
	duofs_flush_buffer(pi, 1, false);
}

static int duofs_increase_btree_height(struct super_block *sb,
		struct duofs_inode *pi, u32 new_height)
{
	u32 height = pi->height;
	__le64 *root, prev_root = pi->root;
	unsigned long blocknr;
	int errval = 0;

	duofs_dbg_verbose("increasing tree height %x:%x\n", height, new_height);
	while (height < new_height) {
		/* allocate the meta block */
		errval = duofs_new_blocks(sb, &blocknr, 1,
					 DUOFS_BLOCK_TYPE_4K, 1, ANY_CPU);
		if (errval < 0) {
			duofs_err(sb, "failed to increase btree height\n");
			break;
		}
		blocknr = duofs_get_block_off(sb, blocknr, DUOFS_BLOCK_TYPE_4K);
		root = duofs_get_block(sb, blocknr);
		duofs_memunlock_block(sb, root);
		root[0] = prev_root;
		duofs_memlock_block(sb, root);
		duofs_flush_buffer(root, sizeof(*root), false);
		prev_root = cpu_to_le64(blocknr);
		height++;
	}
	duofs_memunlock_inode(sb, pi);
	pi->root = prev_root;
	pi->height = height;
	duofs_memlock_inode(sb, pi);
	return 0;
}

/* recursive_alloc_blocks: recursively allocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * zero: whether to zero-out the allocated block(s)
 */
static int recursive_alloc_blocks(duofs_transaction_t *trans,
				  struct super_block *sb, struct duofs_inode *pi, __le64 block, u32 height,
				  unsigned long first_blocknr, unsigned long last_blocknr, bool new_node,
				  bool zero, int cpu, int write_path, __le64 *free_blk_list,
				  unsigned long *num_free_blks, void **log_entries,
				  __le64 *log_entry_nums, int *log_entry_idx)
{
	int i, j, errval;
	unsigned int meta_bits = META_BLK_SHIFT, node_bits;
	__le64 *node;
	bool journal_saved = 0;
	unsigned long blocknr, first_blk, last_blk;
	unsigned int first_index, last_index;
	unsigned int flush_bytes;
	int num_blocks = 0;
	int allocated, freed;

	node = duofs_get_block(sb, le64_to_cpu(block));

	node_bits = (height - 1) * meta_bits;

	first_index = first_blocknr >> node_bits;
	last_index = last_blocknr >> node_bits;

	i = first_index;
	while (i <= last_index) {
		if (height == 1) {
			if (node[i] == 0 || (free_blk_list != NULL)) {
				num_blocks = last_index - i + 1;

				/* Break large allocations into 2MB chunks */
				if (num_blocks > 512) {
					num_blocks = 512;
				}

				allocated = duofs_new_data_blocks(sb, pi,
								 &blocknr,
								 num_blocks,
								 zero, cpu,
								 write_path);
				if (allocated <= 0) {
					duofs_dbg("%s: alloc %d blocks failed!, %d\n",
						 __func__, num_blocks, allocated);
					duofs_memunlock_inode(sb, pi);
					pi->i_flags |= cpu_to_le32(
						DUOFS_EOFBLOCKS_FL);
					duofs_memlock_inode(sb, pi);
					errval = allocated;
					return errval;
				}

				if (new_node == 0 && journal_saved == 0) {
					int le_size = (last_index - i + 1) << 3;
					duofs_add_logentry(sb, trans, &node[i],
							  le_size, LE_DATA);

					if (log_entries != NULL) {
						log_entries[*log_entry_idx] = &node[i];
						log_entry_nums[*log_entry_idx] = (last_index - i + 1);
						(*log_entry_idx) += 1;
					}

					journal_saved = 1;
				}
				duofs_memunlock_block(sb, node);

				for (j = i; j < i+allocated; j++) {
					if (free_blk_list != NULL && node[j] != 0) {
						free_blk_list[*num_free_blks] = node[j];
						(*num_free_blks) += 1;
					}

					node[j] = cpu_to_le64(duofs_get_block_off(sb,
										 blocknr,
										 pi->i_blk_type));
					blocknr++;
				}

				if (free_blk_list != NULL && (*num_free_blks != 0)) {
					unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
					duofs_memunlock_inode(sb, pi);
					pi->i_blocks -= ((*num_free_blks) <<
							 (data_bits - sb->s_blocksize_bits));
					duofs_memunlock_inode(sb, pi);
				}
				duofs_memlock_block(sb, node);
				i += allocated;
			} else {
				i++;
			}
		} else {
			if (node[i] == 0) {
				/* allocate the meta block */
				errval = duofs_new_blocks(sb, &blocknr, 1,
							 DUOFS_BLOCK_TYPE_4K,
							 1, cpu);
				if (errval < 0) {
					duofs_dbg_verbose("alloc meta blk"
						" failed\n");
					goto fail;
				}
				/* save the meta-data into the journal before
				 * modifying */
				if (new_node == 0 && journal_saved == 0) {
					int le_size = (last_index - i + 1) << 3;
					duofs_add_logentry(sb, trans, &node[i],
						le_size, LE_DATA);
					journal_saved = 1;
				}
				duofs_memunlock_block(sb, node);
				node[i] = cpu_to_le64(duofs_get_block_off(sb,
					    blocknr, DUOFS_BLOCK_TYPE_4K));
				duofs_memlock_block(sb, node);
				new_node = 1;
			}

			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			errval = recursive_alloc_blocks(trans, sb, pi, node[i],
							height - 1, first_blk,
							last_blk, new_node,
							zero, cpu, write_path,
							free_blk_list, num_free_blks,
							log_entries, log_entry_nums,
							log_entry_idx);
			if (errval < 0)
				goto fail;
			i++;
		}
	}

	if (new_node || trans == NULL) {
		/* if the changes were not logged, flush the cachelines we may
	 	* have modified */
		flush_bytes = (last_index - first_index + 1) * sizeof(node[0]);
		duofs_flush_buffer(&node[first_index], flush_bytes, false);
	}
	errval = 0;
fail:
	return errval;
}

int __duofs_alloc_blocks(duofs_transaction_t *trans, struct super_block *sb,
			struct duofs_inode *pi, unsigned long file_blocknr, unsigned int num,
			bool zero, int cpu, int write_path,
			__le64 *free_blk_list, unsigned long *num_free_blks,
			void **log_entries, __le64 *log_entry_nums, int *log_entry_idx)
{
	int errval;
	unsigned long max_blocks;
	unsigned int height;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int blk_shift, meta_bits = META_BLK_SHIFT;
	unsigned long blocknr, first_blocknr, last_blocknr, total_blocks;
	timing_t alloc_time;

	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - sb->s_blocksize_bits;

	DUOFS_START_TIMING(alloc_blocks_t, alloc_time);
	first_blocknr = file_blocknr >> blk_shift;
	last_blocknr = (file_blocknr + num - 1) >> blk_shift;

	duofs_dbg_verbose("alloc_blocks height %d file_blocknr %lx num %x, "
		   "first blocknr 0x%lx, last_blocknr 0x%lx\n",
		   pi->height, file_blocknr, num, first_blocknr, last_blocknr);

	height = pi->height;

	blk_shift = height * meta_bits;

	max_blocks = 0x1UL << blk_shift;

	if (last_blocknr > max_blocks - 1) {
		/* B-tree height increases as a result of this allocation */
		total_blocks = last_blocknr >> blk_shift;
		while (total_blocks > 0) {
			total_blocks = total_blocks >> meta_bits;
			height++;
		}
		if (height > 3) {
			duofs_dbg("[%s:%d] Max file size. Cant grow the file\n",
				__func__, __LINE__);
			errval = -ENOSPC;
			goto fail;
		}
	}

	if (!pi->root) {
		if (height == 0) {
			__le64 root;
			errval = duofs_new_data_blocks(sb, pi, &blocknr,
						      1, zero, cpu, write_path);
			if (errval < 0) {
				duofs_dbg_verbose("[%s:%d] failed: alloc data"
					" block\n", __func__, __LINE__);
				goto fail;
			}
			root = cpu_to_le64(duofs_get_block_off(sb, blocknr,
					   pi->i_blk_type));
			duofs_memunlock_inode(sb, pi);
			pi->root = root;
			pi->height = height;
			duofs_memlock_inode(sb, pi);
		} else {
			errval = duofs_increase_btree_height(sb, pi, height);
			if (errval) {
				duofs_dbg_verbose("[%s:%d] failed: inc btree"
					" height\n", __func__, __LINE__);
				goto fail;
			}
			errval = recursive_alloc_blocks(trans, sb, pi, pi->root,
							pi->height, first_blocknr,
							last_blocknr, 1, zero, cpu,
							write_path, free_blk_list,
							num_free_blks,
							log_entries, log_entry_nums,
							log_entry_idx);
			if (errval < 0)
				goto fail;
		}
	} else {
		/* Go forward only if the height of the tree is non-zero. */
		if (height == 0)
			return 0;

		if (height > pi->height) {
			errval = duofs_increase_btree_height(sb, pi, height);
			if (errval) {
				duofs_dbg_verbose("Err: inc height %x:%x tot %lx"
					"\n", pi->height, height, total_blocks);
				goto fail;
			}
		}
		errval = recursive_alloc_blocks(trans, sb, pi, pi->root, height,
						first_blocknr, last_blocknr,
						0, zero, cpu, write_path,
						free_blk_list, num_free_blks,
						log_entries, log_entry_nums,
						log_entry_idx);
		if (errval < 0)
			goto fail;
	}
	DUOFS_END_TIMING(alloc_blocks_t, alloc_time);
	return 0;
fail:
	DUOFS_END_TIMING(alloc_blocks_t, alloc_time);
	return errval;
}

int __duofs_alloc_blocks_wrapper(duofs_transaction_t *trans, struct super_block *sb,
			struct duofs_inode *pi, unsigned long file_blocknr, unsigned int num,
				bool zero, int cpu, int write_path)
{

	return __duofs_alloc_blocks(trans, sb, pi, file_blocknr, num,
				   zero, cpu, write_path,
				   NULL, NULL, NULL, NULL, NULL);
}

/*
 * Allocate num data blocks for inode, starting at given file-relative
 * block number.
 */
inline int duofs_alloc_blocks(duofs_transaction_t *trans, struct inode *inode,
			     unsigned long file_blocknr, unsigned int num,
			     bool zero, int cpu, int write_path,
			     __le64 *free_blk_list, unsigned long *num_free_blks,
			     void **log_entries, __le64 *log_entry_nums,
			     int *log_entry_idx)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	int errval;

	errval = __duofs_alloc_blocks(trans, sb, pi, file_blocknr,
				     num, zero, cpu, write_path,
				     free_blk_list, num_free_blks,
				     log_entries, log_entry_nums,
				     log_entry_idx);

	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	return errval;
}

/*
 * Allocate num data blocks for inode, starting at given file-relative
 * block number.
 */
inline int duofs_alloc_blocks_weak(duofs_transaction_t *trans, struct inode *inode,
				  unsigned long file_blocknr, unsigned int num,
				  bool zero, int cpu, int write_path)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	int errval;

	errval = __duofs_alloc_blocks_wrapper(trans, sb, pi, file_blocknr,
					     num, zero, cpu, write_path);

	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	return errval;
}

static int duofs_alloc_inode_table(struct super_block *sb)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct inode_table *inode_table;
	unsigned long blocknr;
	u64 block;
	int allocated;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		inode_table = duofs_get_inode_table_log(sb, i);
		allocated = duofs_new_blocks(sb, &blocknr, 1,
					    DUOFS_BLOCK_TYPE_2M,
					    1, i);

		duofs_dbg_verbose("%s: allocated block @ 0x%lx\n", __func__,
				  blocknr);

		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = duofs_get_block_off(sb, blocknr, DUOFS_BLOCK_TYPE_2M);
		duofs_memunlock_range(sb, inode_table, CACHELINE_SIZE);
		inode_table->log_head = block;
		duofs_memlock_range(sb, inode_table, CACHELINE_SIZE);
		duofs_flush_buffer(inode_table, CACHELINE_SIZE, 0);
	}

	return 0;
}

/* Initialize the inode table. The duofs_inode struct corresponding to the
 * inode table has already been zero'd out */
int duofs_init_inode_table(struct super_block *sb)
{
	struct duofs_inode *pi = duofs_get_inode_table(sb);
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	unsigned long num_blocks = 0, init_inode_table_size;
	int errval;

	if (sbi->num_inodes == 0) {
		/* initial inode table size was not specified. */
		if (sbi->initsize >= DUOFS_LARGE_INODE_TABLE_THREASHOLD)
			init_inode_table_size = DUOFS_LARGE_INODE_TABLE_SIZE;
		else
			init_inode_table_size = DUOFS_DEF_BLOCK_SIZE_4K;
	} else {
		init_inode_table_size = sbi->num_inodes << DUOFS_INODE_BITS;
	}

	duofs_memunlock_inode(sb, pi);
	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;
	pi->height = 0;
	pi->i_dtime = 0;
	pi->i_blk_type = DUOFS_BLOCK_TYPE_2M;

	/* duofs_sync_inode(pi); */
	duofs_memlock_inode(sb, pi);

	errval = duofs_alloc_inode_table(sb);

	PERSISTENT_BARRIER();
	return errval;
}

inline int duofs_insert_inodetree(struct duofs_sb_info *sbi,
				 struct duofs_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = duofs_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		duofs_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

inline int duofs_search_inodetree(struct duofs_sb_info *sbi,
				 unsigned long ino, struct duofs_range_node **ret_node)
{
	struct rb_root *tree;
	unsigned long internal_ino;
	int cpu;

	cpu = ino % sbi->cpus;
	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	internal_ino = ino / sbi->cpus;
	return duofs_find_range_node(tree, internal_ino,
				    NODE_INODE, ret_node);
}

static int duofs_read_inode(struct inode *inode, struct duofs_inode *pi)
{
	int ret = -EIO;
	struct duofs_inode_info *si = DUOFS_I(inode);
	struct duofs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;

	inode->i_mode = le16_to_cpu(pi->i_mode);
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	inode->i_size = le64_to_cpu(pi->i_size);
	inode->i_atime.tv_sec = le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	inode->i_generation = le32_to_cpu(pi->i_generation);
	duofs_set_inode_flags(inode, pi);

	/* check if the inode is active. */
	if (inode->i_nlink == 0 &&
	   (inode->i_mode == 0 || le32_to_cpu(pi->i_dtime))) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	duofs_init_header(sb, sih, __le16_to_cpu(pi->i_mode));
	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	inode->i_mapping->a_ops = &duofs_aops_xip;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &duofs_file_inode_operations;
		inode->i_fop = &duofs_xip_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &duofs_dir_inode_operations;
		inode->i_fop = &duofs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &duofs_symlink_inode_operations;
		break;
	default:
		inode->i_size = 0;
		inode->i_op = &duofs_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   le32_to_cpu(pi->dev.rdev));
		break;
	}

	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

static void duofs_update_inode(struct inode *inode, struct duofs_inode *pi)
{
	duofs_memunlock_inode(inode->i_sb, pi);
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_generation = cpu_to_le32(inode->i_generation);
	duofs_get_inode_flags(inode, pi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->dev.rdev = cpu_to_le32(inode->i_rdev);

	duofs_memlock_inode(inode->i_sb, pi);
}

static int duofs_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct inode_map *inode_map;
	struct duofs_range_node *i = NULL;
	struct duofs_range_node *curr_node;
	int cpuid = ino % sbi->cpus;
	unsigned long internal_ino = ino / sbi->cpus;
	int found = 0;
	int ret = 0;

	duofs_dbg_verbose("Free inuse ino: %lu\n", ino);
	inode_map = &sbi->inode_maps[cpuid];

	mutex_lock(&inode_map->inode_table_mutex);
	found = duofs_search_inodetree(sbi, ino, &i);
	if (!found) {
		duofs_dbg("%s ERROR: ino %lu not found\n", __func__, ino);
		mutex_unlock(&inode_map->inode_table_mutex);
		return -EINVAL;
	}

	if ((internal_ino == i->range_low) && (internal_ino == i->range_high)) {
		/* fits entire node */
		rb_erase(&i->node, &inode_map->inode_inuse_tree);
		duofs_free_inode_node(i);
		inode_map->num_range_node_inode--;
		goto block_found;
	}
	if ((internal_ino == i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns left */
		i->range_low = internal_ino + 1;
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino == i->range_high)) {
		/* Aligns right */
		i->range_high = internal_ino - 1;
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns somewhere in the middle */
		curr_node = duofs_alloc_inode_node(sb);
		DUOFS_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block */
			goto block_found;
		}
		curr_node->range_low = internal_ino + 1;
		curr_node->range_high = i->range_high;

		i->range_high = internal_ino - 1;

		ret = duofs_insert_inodetree(sbi, curr_node, cpuid);
		if (ret) {
			duofs_free_inode_node(curr_node);
			goto err;
		}
		inode_map->num_range_node_inode++;
		goto block_found;
	}

err:
	duofs_error_mng(sb, "Unable to free inode %lu\n", ino);
	duofs_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->range_low, i->range_high);
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;

block_found:
	sbi->s_inodes_used_count--;
	inode_map->freed++;
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 */
static int duofs_free_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct duofs_inode *pi;
	unsigned long inode_nr;
	duofs_transaction_t *trans;
	int err = 0;
	struct duofs_inode_info *si;
	struct duofs_inode_info_header *sih = NULL;

	//mutex_lock(&DUOFS_SB(sb)->inode_table_mutex);

	duofs_dbg_verbose("free_inode: %lx free_nodes %x tot nodes %x hint %x\n",
		   inode->i_ino, sbi->s_free_inodes_count, sbi->s_inodes_count,
		   sbi->s_free_inode_hint);
	inode_nr = inode->i_ino;

	pi = duofs_get_inode(sb, inode->i_ino);

	trans = duofs_new_transaction(sb, MAX_INODE_LENTRIES, duofs_get_cpuid(sb));
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto out;
	}

	duofs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	duofs_memunlock_inode(sb, pi);
	pi->root = 0;
	/* pi->i_links_count = 0;
	pi->i_xattr = 0; */
	pi->i_size = 0;
	pi->i_dtime = cpu_to_le32(get_seconds());
	duofs_memlock_inode(sb, pi);

	duofs_commit_transaction(sb, trans);

	/* increment s_free_inodes_count */
	if (inode_nr < (sbi->s_free_inode_hint))
		sbi->s_free_inode_hint = (inode_nr);

	sbi->s_free_inodes_count += 1;

	/*
	if ((sbi->s_free_inodes_count) ==
	    (sbi->s_inodes_count) - duofs_FREE_INODE_HINT_START) {
		duofs_dbg_verbose("fs is empty!\n");
		sbi->s_free_inode_hint = (duofs_FREE_INODE_HINT_START);
	}
	*/

	duofs_dbg_verbose("free_inode: free_nodes %x total_nodes %x hint %x\n",
		   sbi->s_free_inodes_count, sbi->s_inodes_count,
		   sbi->s_free_inode_hint);
out:

	si = DUOFS_I(inode);
	sih = &si->header;

	sih->i_mode = 0;
	sih->i_size = 0;
	sih->i_blocks = 0;

	err = duofs_free_inuse_inode(sb, inode->i_ino);

	//mutex_unlock(&DUOFS_SB(sb)->inode_table_mutex);

	return err;
}

struct inode *duofs_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct duofs_inode *pi;
	int err;
	struct duofs_inode_info *si;
	struct duofs_inode_info_header *sih = NULL;


	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	pi = duofs_get_inode(sb, ino);
	if (!pi) {
		err = -EACCES;
		goto fail;
	}

	err = duofs_read_inode(inode, pi);
	if (unlikely(err))
		goto fail;
	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

static int duofs_free_dram_resource(struct super_block *sb,
	struct duofs_inode_info_header *sih)
{
	int freed = 0;

	if (sih->ino == 0)
		return 0;

	if (!(S_ISDIR(sih->i_mode)))
		return 0;

	duofs_delete_dir_tree(sb, sih);
	freed = 1;
	return freed;
}

static int duofs_free_inode_resource(struct super_block *sb,
				    struct duofs_inode *pi, struct duofs_inode_info_header *sih,
				    struct inode *inode)
{
	unsigned long last_blocknr;
	int ret = 0;
	int freed = 0;

	duofs_memlock_inode(sb, pi);

	switch(__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFDIR:
		duofs_dbg_verbose("%s: dir ino %lu\n", __func__, sih->ino);
		duofs_delete_dir_tree(sb, sih);
		break;
	default:
		break;
	}

	duofs_dbg_verbose("%s: Freed %d\n", __func__, freed);
	/* Then we can free the inode */
	ret = duofs_free_inode(inode);
	if (ret) {
		duofs_err(sb, "%s: free inode %lu failed\n",
			 __func__, sih->ino);
	}

	return ret;
}

void duofs_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	__le64 root;
	unsigned long last_blocknr;
	unsigned int height, btype;
	int err = 0;
	timing_t evict_time;
	struct duofs_inode_info *si;
	struct duofs_inode_info_header *sih = NULL;
	int destroy = 0;

	si = DUOFS_I(inode);
	sih = &si->header;

	DUOFS_START_TIMING(evict_inode_t, evict_time);
	if (!inode->i_nlink && !is_bad_inode(inode)) {
		if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
			S_ISLNK(inode->i_mode)))
			goto out;
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
			goto out;

		root = pi->root;
		height = pi->height;
		btype = pi->i_blk_type;

		if (pi->i_flags & cpu_to_le32(DUOFS_EOFBLOCKS_FL)) {
			last_blocknr = (1UL << (pi->height * META_BLK_SHIFT))
			    - 1;
		} else {
			if (likely(inode->i_size))
				last_blocknr = (inode->i_size - 1) >>
					duofs_inode_blk_shift(pi);
			else
				last_blocknr = 0;
			last_blocknr = duofs_sparse_last_blocknr(pi->height,
				last_blocknr);
		}

		/* first free the inode */
		if (pi) {
			err = duofs_free_inode_resource(sb, pi, sih, inode);
			if (err)
				goto out;
		}

		destroy = 1;
		pi = NULL; /* we no longer own the duofs_inode */

		/* then free the blocks from the inode's b-tree */
		duofs_free_inode_subtree(sb, root, height, btype, last_blocknr);
		inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_size = 0;
	}
out:
	if (destroy == 0) {
		duofs_dbg_verbose("%s: destroying %lu\n", __func__, inode->i_ino);
		duofs_free_dram_resource(sb, sih);
	}
	/* now it is safe to remove the inode from the truncate list */
	duofs_truncate_del(inode);
	/* TODO: Since we don't use page-cache, do we really need the following
	 * call? */
	truncate_inode_pages(&inode->i_data, 0);

	clear_inode(inode);
	DUOFS_END_TIMING(evict_inode_t, evict_time);
}

static int duofs_alloc_unused_inode(struct super_block *sb, int cpuid,
				   unsigned long *ino)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct inode_map *inode_map;
	struct duofs_range_node *i, *next_i;
	struct rb_node *temp, *next;
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	inode_map = &sbi->inode_maps[cpuid];
	i = inode_map->first_inode_range;
	DUOFS_ASSERT(i);

	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = MAX_INODE;
	} else {
		next_i = container_of(next, struct duofs_range_node, node);
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		/* Fill the gap completely */
		i->range_high = next_i->range_high;
		rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
		duofs_free_inode_node(next_i);
		inode_map->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		/* Aligns to left */
		i->range_high = new_ino;
	} else {
		duofs_dbg("%s: ERROR: new ino %lu, next low %lu\n", __func__,
			new_ino, next_range_low);
		return -ENOSPC;
	}

	*ino = new_ino * sbi->cpus + cpuid;
	sbi->s_inodes_used_count++;
	inode_map->allocated++;

	duofs_dbg_verbose("Alloc ino %lu\n", *ino);
	return 0;
}

static int duofs_increase_inode_table_size(struct super_block *sb)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct duofs_inode *pi = duofs_get_inode_table(sb);
	duofs_transaction_t *trans;
	int errval;

#if 0
	/* 1 log entry for inode-table inode, 1 lentry for inode-table b-tree */
	trans = duofs_new_transaction(sb, MAX_INODE_LENTRIES, duofs_get_cpuid(sb));
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	duofs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	errval = __duofs_alloc_blocks_wrapper(trans, sb, pi,
			le64_to_cpup(&pi->i_size) >> sb->s_blocksize_bits,
				     1, true, 0);

	if (errval == 0) {
		u64 i_size = le64_to_cpu(pi->i_size);

		sbi->s_free_inode_hint = i_size >> duofs_INODE_BITS;
		i_size += duofs_inode_blk_size(pi);

		duofs_memunlock_inode(sb, pi);
		pi->i_size = cpu_to_le64(i_size);
		duofs_memlock_inode(sb, pi);

		sbi->s_free_inodes_count += INODES_PER_BLOCK(pi->i_blk_type);
		sbi->s_inodes_count = i_size >> duofs_INODE_BITS;
	} else
		duofs_dbg_verbose("no space left to inc inode table!\n");
	/* commit the transaction */
	duofs_commit_transaction(sb, trans);
#endif
	return errval;
}

struct inode *duofs_new_inode(duofs_transaction_t *trans, struct inode *dir,
		umode_t mode, const struct qstr *qstr)
{
	struct super_block *sb;
	struct duofs_sb_info *sbi;
	struct inode *inode;
	struct duofs_inode *pi = NULL;
	struct inode_map *inode_map;
	struct duofs_inode *diri = NULL, *inode_table;
	int i, errval;
	u32 num_inodes, inodes_per_block;
	ino_t ino = 0;
	struct duofs_inode_info *si;
	struct duofs_inode_info_header *sih = NULL;
	unsigned long free_ino = 0;
	int map_id;
	struct process_numa *proc_numa, *parent_proc_numa;
	pid_t parent_pid;
	struct task_struct *parent_task;
	int parent_cpu, parent_numa;

	sb = dir->i_sb;
	sbi = (struct duofs_sb_info *)sb->s_fs_info;
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

	inode->i_generation = atomic_add_return(1, &sbi->next_generation);

	inode_table = duofs_get_inode_table(sb);

	duofs_dbg_verbose("inode: %p free_inodes %x total_inodes %x hint %x\n",
		inode, sbi->s_free_inodes_count, sbi->s_inodes_count,
		sbi->s_free_inode_hint);

	diri = duofs_get_inode(sb, dir->i_ino);
	if (!diri)
		return ERR_PTR(-EACCES);

	map_id = sbi->map_id;
	sbi->map_id = (sbi->map_id + 1) % sbi->cpus;
	inode_map = &sbi->inode_maps[map_id];
	mutex_lock(&inode_map->inode_table_mutex);

	num_inodes = (sbi->s_inodes_count);
	errval = duofs_alloc_unused_inode(sb, map_id, &free_ino);
	if (errval) {
		duofs_dbg("%s: alloc inode number failed %d\n", __func__, errval);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	/* FIXME: Should handle this part */

	mutex_unlock(&inode_map->inode_table_mutex);
	ino = free_ino;

	pi = duofs_get_inode(sb, ino);
	duofs_dbg_verbose("%s: ino = %lu, duofs_inode = 0x%p", __func__, ino, pi);

	duofs_dbg_verbose("allocating inode %lx\n", ino);

	/* chosen inode is in ino */
	inode->i_ino = ino;
	duofs_add_logentry(sb, trans, pi, sizeof(*pi), LE_DATA);

	duofs_memunlock_inode(sb, pi);
	pi->i_blk_type = DUOFS_DEFAULT_BLOCK_TYPE;
	pi->i_flags = duofs_mask_flags(mode, diri->i_flags);
	pi->height = 0;
	pi->i_dtime = 0;
	pi->huge_aligned_file = 0;
	proc_numa = &(sbi->process_numa[current->tgid % sbi->num_parallel_procs]);
	if (proc_numa->tgid != current->tgid) {
		proc_numa->tgid = current->tgid;

		parent_pid = task_ppid_nr(current);
		parent_task = find_task_by_pid_ns(parent_pid, &init_pid_ns);
		parent_proc_numa = &(sbi->process_numa[parent_task->tgid % sbi->num_parallel_procs]);

		if (parent_proc_numa->tgid != parent_task->tgid)
			proc_numa->numa_node = duofs_get_free_numa_node(sb);
		else
			proc_numa->numa_node = parent_proc_numa->numa_node;
	}

	pi->numa_node = proc_numa->numa_node;
	duofs_memlock_inode(sb, pi);

	sbi->s_free_inodes_count -= 1;

	duofs_update_inode(inode, pi);

	si = DUOFS_I(inode);
	sih = &si->header;
	duofs_init_header(sb, sih, inode->i_mode);
	sih->ino = ino;
	sih->i_blk_type = DUOFS_DEFAULT_BLOCK_TYPE;

	duofs_set_inode_flags(inode, pi);
	sih->i_flags = le32_to_cpu(pi->i_flags);

	if (insert_inode_locked(inode) < 0) {
		duofs_err(sb, "duofs_new_inode failed ino %lx\n", inode->i_ino);
		errval = -EINVAL;
		goto fail1;
	}

	return inode;
fail1:
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(errval);
}

inline void duofs_update_nlink(struct inode *inode, struct duofs_inode *pi)
{
	duofs_memunlock_inode(inode->i_sb, pi);
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	duofs_memlock_inode(inode->i_sb, pi);
}

inline void duofs_update_isize(struct inode *inode, struct duofs_inode *pi)
{
	duofs_memunlock_inode(inode->i_sb, pi);
	pi->i_size = cpu_to_le64(inode->i_size);
	duofs_memlock_inode(inode->i_sb, pi);
}

inline void duofs_update_time(struct inode *inode, struct duofs_inode *pi)
{
	duofs_memunlock_inode(inode->i_sb, pi);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	duofs_memlock_inode(inode->i_sb, pi);
}

/* This function checks if VFS's inode and duofs's inode are not in sync */
static bool duofs_is_inode_dirty(struct inode *inode, struct duofs_inode *pi)
{
	if (inode->i_ctime.tv_sec != le32_to_cpu(pi->i_ctime) ||
		inode->i_mtime.tv_sec != le32_to_cpu(pi->i_mtime) ||
		inode->i_size != le64_to_cpu(pi->i_size) ||
		inode->i_mode != le16_to_cpu(pi->i_mode) ||
		i_uid_read(inode) != le32_to_cpu(pi->i_uid) ||
		i_gid_read(inode) != le32_to_cpu(pi->i_gid) ||
		inode->i_nlink != le16_to_cpu(pi->i_links_count) ||
		inode->i_blocks != le64_to_cpu(pi->i_blocks) ||
		inode->i_atime.tv_sec != le32_to_cpu(pi->i_atime))
		return true;
	return false;
}

int duofs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* write_inode should never be called because we always keep our inodes
	 * clean. So let us know if write_inode ever gets called. */
//	BUG();
	return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because duofs always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void duofs_dirty_inode(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);

	/* only i_atime should have changed if at all.
	 * we can do in-place atomic update */
	duofs_memunlock_inode(sb, pi);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	duofs_memlock_inode(sb, pi);
	duofs_flush_buffer(&pi->i_atime, sizeof(pi->i_atime), true);
}

/*
 * Called to zeros out a single block. It's used in the "resize"
 * to avoid to keep data in case the file grow up again.
 */
/* Make sure to zero out just a single 4K page in case of 2M or 1G blocks */
static void duofs_block_truncate_page(struct inode *inode, loff_t newsize)
{
	struct super_block *sb = inode->i_sb;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long blocknr, length;
	u64 blockoff;
	char *bp;

	/* Block boundary or extending ? */
	if (!offset || newsize > inode->i_size)
		return;

	length = sb->s_blocksize - offset;
	blocknr = newsize >> sb->s_blocksize_bits;

	duofs_find_data_blocks(inode, blocknr, &blockoff, 1);

	/* Hole ? */
	if (!blockoff)
		return;

	bp = duofs_get_block(sb, blockoff);
	if (!bp)
		return;
	duofs_memunlock_block(sb, bp);
	memset(bp + offset, 0, length);
	duofs_memlock_block(sb, bp);
	duofs_flush_buffer(bp + offset, length, false);
}

void duofs_truncate_del(struct inode *inode)
{
	struct list_head *prev;
	struct duofs_inode_info *si = DUOFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct duofs_inode_truncate_item *head = duofs_get_truncate_list_head(sb);
	struct duofs_inode_truncate_item *li;
	unsigned long ino_next;

	mutex_lock(&sbi->s_truncate_lock);
	if (list_empty(&si->i_truncated))
		goto out;
	/* Make sure all truncate operation is persistent before removing the
	 * inode from the truncate list */
	PERSISTENT_MARK();

	li = duofs_get_truncate_item(sb, inode->i_ino);

	ino_next = le64_to_cpu(li->i_next_truncate);
	prev = si->i_truncated.prev;

	list_del_init(&si->i_truncated);
	PERSISTENT_BARRIER();

	/* Atomically delete the inode from the truncate list */
	if (prev == &sbi->s_truncate) {
		duofs_memunlock_range(sb, head, sizeof(*head));
		head->i_next_truncate = cpu_to_le64(ino_next);
		duofs_memlock_range(sb, head, sizeof(*head));
		duofs_flush_buffer(&head->i_next_truncate,
			sizeof(head->i_next_truncate), false);
	} else {
		struct inode *i_prv = &list_entry(prev,
			struct duofs_inode_info, i_truncated)->vfs_inode;
		struct duofs_inode_truncate_item *li_prv = 
				duofs_get_truncate_item(sb, i_prv->i_ino);
		duofs_memunlock_range(sb, li_prv, sizeof(*li_prv));
		li_prv->i_next_truncate = cpu_to_le64(ino_next);
		duofs_memlock_range(sb, li_prv, sizeof(*li_prv));
		duofs_flush_buffer(&li_prv->i_next_truncate,
			sizeof(li_prv->i_next_truncate), false);
	}
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
out:
	mutex_unlock(&sbi->s_truncate_lock);
}

/* duofs maintains a so-called truncate list, which is a linked list of inodes
 * which require further processing in case of a power failure. Currently, duofs
 * uses the truncate list for two purposes.
 * 1) When removing a file, if the i_links_count becomes zero (i.e., the file
 * is not referenced by any directory entry), the inode needs to be freed.
 * However, if the file is currently in use (e.g., opened) it can't be freed
 * until all references are closed. Hence duofs adds the inode to the truncate
 * list during directory entry removal, and removes it from the truncate list
 * when VFS calls evict_inode. If a power failure happens before evict_inode,
 * the inode is freed during the next mount when we recover the truncate list
 * 2) When truncating a file (reducing the file size and freeing the blocks),
 * we don't want to return the freed blocks to the free list until the whole
 * truncate operation is complete. So we add the inode to the truncate list with
 * the specified truncate_size. Now we can return freed blocks to the free list
 * even before the transaction is complete. Because if a power failure happens
 * before freeing of all the blocks is complete, duofs will free the remaining
 * blocks during the next mount when we recover the truncate list */
void duofs_truncate_add(struct inode *inode, u64 truncate_size)
{
	struct super_block *sb = inode->i_sb;
	struct duofs_inode_truncate_item *head = duofs_get_truncate_list_head(sb);
	struct duofs_inode_truncate_item *li;

	mutex_lock(&DUOFS_SB(sb)->s_truncate_lock);
	if (!list_empty(&DUOFS_I(inode)->i_truncated))
		goto out_unlock;

	li = duofs_get_truncate_item(sb, inode->i_ino);

	duofs_memunlock_range(sb, li, sizeof(*li));
	li->i_next_truncate = head->i_next_truncate;
	li->i_truncatesize = cpu_to_le64(truncate_size);
	duofs_memlock_range(sb, li, sizeof(*li));
	duofs_flush_buffer(li, sizeof(*li), false);
	/* make sure above is persistent before changing the head pointer */
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	/* Atomically insert this inode at the head of the truncate list. */
	duofs_memunlock_range(sb, head, sizeof(*head));
	head->i_next_truncate = cpu_to_le64(inode->i_ino);
	duofs_memlock_range(sb, head, sizeof(*head));
	duofs_flush_buffer(&head->i_next_truncate,
		sizeof(head->i_next_truncate), false);
	/* No need to make the head persistent here if we are called from
	 * within a transaction, because the transaction will provide a
	 * subsequent persistent barrier */
	if (duofs_current_transaction() == NULL) {
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}
	list_add(&DUOFS_I(inode)->i_truncated, &DUOFS_SB(sb)->s_truncate);

out_unlock:
	mutex_unlock(&DUOFS_SB(sb)->s_truncate_lock);
}

void duofs_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize = inode->i_size;

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	      S_ISLNK(inode->i_mode))) {
		duofs_err(inode->i_sb, "%s:wrong file mode %x\n", inode->i_mode);
		return;
	}

	if (newsize != oldsize) {
		duofs_block_truncate_page(inode, newsize);
		i_size_write(inode, newsize);
	}
	/* FIXME: we should make sure that there is nobody reading the inode
	 * before truncating it. Also we need to munmap the truncated range
	 * from application address space, if mmapped. */
	/* synchronize_rcu(); */
	__duofs_truncate_blocks(inode, newsize, oldsize);
	/* No need to make the b-tree persistent here if we are called from
	 * within a transaction, because the transaction will provide a
	 * subsequent persistent barrier */
	if (duofs_current_transaction() == NULL) {
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}
}

int duofs_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int flags)
{
	struct inode *inode;

	inode = path->dentry->d_inode;
	generic_fillattr(inode, stat);
	/* stat->blocks should be the number of 512B blocks */
	stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
	return 0;
}

/* update a single inode field atomically without using a transaction */
static int duofs_update_single_field(struct super_block *sb, struct inode *inode,
	struct duofs_inode *pi, unsigned int ia_valid)
{
	duofs_memunlock_inode(sb, pi);
	switch (ia_valid) {
		case ATTR_MODE:
			pi->i_mode = cpu_to_le16(inode->i_mode);
			break;
		case ATTR_UID:
			pi->i_uid = cpu_to_le32(i_uid_read(inode));
			break;
		case ATTR_GID:
			pi->i_gid = cpu_to_le32(i_gid_read(inode));
			break;
		case ATTR_SIZE:
			pi->i_size = cpu_to_le64(inode->i_size);
			break;
		case ATTR_ATIME:
			pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
			break;
		case ATTR_CTIME:
			pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
			break;
		case ATTR_MTIME:
			pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
			break;
	}
	duofs_memlock_inode(sb, pi);
	duofs_flush_buffer(pi, sizeof(*pi), true);
	return 0;
}

int duofs_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct duofs_inode *pi = duofs_get_inode(sb, inode->i_ino);
	duofs_transaction_t *trans;
	int ret;
	unsigned int ia_valid = attr->ia_valid, attr_mask;

	if (!pi)
		return -EACCES;

	ret = setattr_prepare(dentry, attr);
	if (ret)
		return ret;

	if ((ia_valid & ATTR_SIZE) && (attr->ia_size != inode->i_size ||
			pi->i_flags & cpu_to_le32(DUOFS_EOFBLOCKS_FL))) {

		duofs_truncate_add(inode, attr->ia_size);
		/* set allocation hint */
		//duofs_set_blocksize_hint(sb, pi, attr->ia_size);

		/* now we can freely truncate the inode */
		duofs_setsize(inode, attr->ia_size);
		duofs_update_isize(inode, pi);
		duofs_flush_buffer(pi, CACHELINE_SIZE, false);
		/* we have also updated the i_ctime and i_mtime, so no
		 * need to update them again */
		ia_valid = ia_valid & ~(ATTR_CTIME | ATTR_MTIME);
		/* now it is safe to remove the inode from the truncate list */
		duofs_truncate_del(inode);
	}
	setattr_copy(inode, attr);

	/* we have already handled ATTR_SIZE above so no need to check for it */
	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_ATIME | ATTR_MTIME |
		ATTR_CTIME;

	ia_valid = ia_valid & attr_mask;

	if (ia_valid == 0)
		return ret;
	/* check if we need to update only a single field. we could avoid using
	 * a transaction */
	if ((ia_valid & (ia_valid - 1)) == 0) {
		duofs_update_single_field(sb, inode, pi, ia_valid);
		return ret;
	}

	BUG_ON(duofs_current_transaction());
	/* multiple fields are modified. Use a transaction for atomicity */
	trans = duofs_new_transaction(sb, MAX_INODE_LENTRIES, duofs_get_cpuid(sb));
	if (IS_ERR(trans))
		return PTR_ERR(trans);
	duofs_add_logentry(sb, trans, pi, sizeof(*pi), LE_DATA);

	duofs_update_inode(inode, pi);

	duofs_commit_transaction(sb, trans);

	return ret;
}

void duofs_set_inode_flags(struct inode *inode, struct duofs_inode *pi)
{
	unsigned int flags = le32_to_cpu(pi->i_flags);

	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;
}

void duofs_get_inode_flags(struct inode *inode, struct duofs_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int duofs_flags = le32_to_cpu(pi->i_flags);

	duofs_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
			 FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		duofs_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		duofs_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		duofs_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		duofs_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		duofs_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_le32(duofs_flags);
}

static ssize_t duofs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = filp->f_mapping->host;
	loff_t end = iocb->ki_pos;
	ssize_t ret = -EINVAL;
	ssize_t written = 0;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;

	for (seg = 0; seg < nr_segs; seg++) {
		end += iv->iov_len;
		iv++;
	}

	if ((iov_iter_rw(iter) == WRITE) && end > i_size_read(inode)) {
		/* FIXME: Do we need to check for out of bounds IO for R/W */
		printk(KERN_ERR "duofs: needs to grow (size = %lld)\n", end);
		return ret;
	}

	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (iov_iter_rw(iter) == READ) {
			ret = duofs_xip_file_read(filp, iv->iov_base,
					iv->iov_len, &iocb->ki_pos);
		} else if (iov_iter_rw(iter) == WRITE) {
			inode_unlock(inode);
			ret = duofs_xip_file_write(filp, iv->iov_base,
					iv->iov_len, &iocb->ki_pos);
			inode_lock(inode);
		}
		if (ret < 0)
			goto err;

		if (iter->count > iv->iov_len)
			iter->count -= iv->iov_len;
		else
			iter->count = 0;

		written += ret;
		iter->nr_segs--;
		iv++;
	}
	if (iocb->ki_pos != end)
		printk(KERN_ERR "duofs: direct_IO: end = %lld"
			"but offset = %lld\n", end, iocb->ki_pos);
	ret = written;
err:
	return ret;
}

const struct address_space_operations duofs_aops_xip = {
	.direct_IO		= duofs_direct_IO,
	/*.xip_mem_protect	= duofs_xip_mem_protect,*/
};
