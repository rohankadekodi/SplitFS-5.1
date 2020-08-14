/*
 * PMFS emulated persistence. This file contains code to 
 * handle data blocks of various sizes efficiently.
 *
 * Persistent Memory File System
 * Copyright (c) 2012-2013, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include "pmfs.h"
#include "inode.h"

#define PAGES_PER_2MB 512
#define PAGES_PER_2MB_MASK (PAGES_PER_2MB - 1)
#define IS_BLOCK_2MB_ALIGNED(block) \
	(!(block & PAGES_PER_2MB_MASK))

struct scan_bitmap {
	unsigned long bitmap_4k_size;
	unsigned long bitmap_2M_size;
	unsigned long bitmap_1G_size;
	unsigned long *bitmap_4k;
	unsigned long *bitmap_2M;
	unsigned long *bitmap_1G;
};

void pmfs_init_header(struct super_block *sb,
		      struct pmfs_inode_info_header *sih, u16 i_mode)
{
	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->rb_tree = RB_ROOT;
	sih->vma_tree = RB_ROOT;
	sih->num_vmas = 0;
	sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->i_blk_type = PMFS_DEFAULT_BLOCK_TYPE;
	sih->last_dentry = NULL;
}

static inline int get_block_cpuid(struct pmfs_sb_info *sbi,
	unsigned long blocknr)
{
	return blocknr / sbi->per_list_blocks;
}

static void pmfs_clear_datablock_inode(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	pmfs_transaction_t *trans;

	/* 2 log entry for inode */
	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES, pmfs_get_cpuid(sb));
	if (IS_ERR(trans))
		return;
	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	pmfs_memunlock_inode(sb, pi);
	memset(pi, 0, MAX_DATA_PER_LENTRY);
	pmfs_memlock_inode(sb, pi);

	/* commit the transaction */
	pmfs_commit_transaction(sb, trans);
}

static void pmfs_destroy_blocknode_tree(struct super_block *sb, int cpu)
{
	struct free_list *free_list;

	free_list = pmfs_get_free_list(sb, cpu);
	pmfs_destroy_range_node_tree(sb, &free_list->unaligned_block_free_tree);
	pmfs_destroy_range_node_tree(sb, &free_list->huge_aligned_block_free_tree);
}

static void pmfs_init_blockmap_from_inode(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	struct pmfs_range_node_lowhigh *p = NULL;
	struct pmfs_range_node *blknode;
	struct free_list *free_list;
	size_t size = sizeof(struct pmfs_range_node_lowhigh);
	u64 curr_p;
	u64 cpuid;
	unsigned long index;
	unsigned long blocknr;
	unsigned long i;
	unsigned long num_blocknode;
	u64 bp;
	int ret;

	num_blocknode = sbi->num_blocknode_allocated;
	sbi->num_blocknode_allocated = 0;
	for (i=0; i<num_blocknode; i++) {
		index = i & 0xFF;
		if (index == 0) {
			/* Find and get new data block */
			blocknr = i >> 8; /* 256 Entries in a block */
			__pmfs_find_data_blocks(sb, pi, blocknr, &bp, 1);
			p = (struct pmfs_range_node_lowhigh *)pmfs_get_block(sb, bp);
		}
		PMFS_ASSERT(p);
		blknode = pmfs_alloc_blocknode(sb);
		if (blknode == NULL)
                	PMFS_ASSERT(0);
		blknode->range_low = le64_to_cpu(p[index].range_low);
		blknode->range_high = le64_to_cpu(p[index].range_high);

		cpuid = get_block_cpuid(sbi, blknode->range_low);
		free_list = pmfs_get_free_list(sb, cpuid);

		if (IS_BLOCK_2MB_ALIGNED(blknode->range_low) &&
		    (blknode->range_high - blknode->range_low + 1 == PAGES_PER_2MB)) {
			ret = pmfs_insert_blocktree(&free_list->huge_aligned_block_free_tree,
						    blknode);
			free_list->num_blocknode_huge_aligned++;
			if (free_list->num_blocknode_huge_aligned == 1)
				free_list->first_node_huge_aligned = blknode;
		} else {
			ret = pmfs_insert_blocktree(&free_list->unaligned_block_free_tree,
						    blknode);
			free_list->num_blocknode_unaligned++;
			if (free_list->num_blocknode_unaligned == 1)
				free_list->first_node_unaligned = blknode;
		}
		if (ret) {
			pmfs_err(sb, "%s failed\n", __func__);
			pmfs_free_blocknode(blknode);
			PMFS_ASSERT(0);
			pmfs_destroy_blocknode_tree(sb, cpuid);
			return;
		}
		free_list->num_free_blocks +=
			blknode->range_high - blknode->range_low + 1;
		curr_p += sizeof(struct pmfs_range_node_lowhigh);
		//list_add_tail(&blknode->link, &sbi->block_inuse_head);
	}
}

static void pmfs_destroy_inode_trees(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct inode_map *inode_map;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		pmfs_destroy_range_node_tree(sb,
					     &inode_map->inode_inuse_tree);
	}
}

static bool pmfs_can_skip_full_scan(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	__le64 root;
	unsigned int height, btype;
	unsigned long last_blocknr;

	if (!pi->root)
		return false;

	sbi->num_blocknode_allocated =
		le64_to_cpu(super->s_num_blocknode_allocated);
	sbi->num_free_blocks = le64_to_cpu(super->s_num_free_blocks);
	sbi->s_inodes_count = le32_to_cpu(super->s_inodes_count);
	sbi->s_free_inodes_count = le32_to_cpu(super->s_free_inodes_count);
	sbi->s_inodes_used_count = le32_to_cpu(super->s_inodes_used_count);
	sbi->s_free_inode_hint = le32_to_cpu(super->s_free_inode_hint);

	pmfs_init_blockmap_from_inode(sb);

	root = pi->root;
	height = pi->height;
	btype = pi->i_blk_type;
	/* pi->i_size can not be zero */
	last_blocknr = (le64_to_cpu(pi->i_size) - 1) >>
					pmfs_inode_blk_shift(pi);

	/* Clearing the datablock inode */
	pmfs_clear_datablock_inode(sb);

	pmfs_free_inode_subtree(sb, root, height, btype, last_blocknr);

	return true;
}


static int pmfs_allocate_datablock_block_inode(pmfs_transaction_t *trans,
	struct super_block *sb, struct pmfs_inode *pi, unsigned long num_blocks)
{
	int errval;

#if 0

	pmfs_memunlock_inode(sb, pi);
	pi->i_mode = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_blk_type = PMFS_BLOCK_TYPE_4K;
	pi->i_flags = 0;
	pi->height = 0;
	pi->i_dtime = 0;
	pi->i_size = cpu_to_le64(num_blocks << sb->s_blocksize_bits);
	pmfs_memlock_inode(sb, pi);

	errval = __pmfs_alloc_blocks_wrapper(trans, sb, pi, 0,
					     num_blocks, false, 0);
#endif
	return errval;
}

void pmfs_save_blocknode_mappings(struct super_block *sb)
{
#if 0
	unsigned long num_blocks, blocknr;
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	struct pmfs_blocknode_lowhigh *p;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i;
	struct pmfs_super_block *super;
	pmfs_transaction_t *trans;
	u64 bp;
	int j, k;
	int errval;

	num_blocks = ((sbi->num_blocknode_allocated * sizeof(struct
		pmfs_range_node_lowhigh) - 1) >> sb->s_blocksize_bits) + 1;

	/* 2 log entry for inode, 2 lentry for super-block */
	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES + MAX_SB_LENTRIES, 0);
	if (IS_ERR(trans))
		return;

	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	errval = pmfs_allocate_datablock_block_inode(trans, sb, pi, num_blocks);

	if (errval != 0) {
		pmfs_dbg("Error saving the blocknode mappings: %d\n", errval);
		pmfs_abort_transaction(sb, trans);
		return;
	}

	j = 0;
	k = 0;
	p = NULL;
	list_for_each_entry(i, head, link) {
		blocknr = k >> 8;
		if (j == 0) {
			/* Find, get and unlock new data block */
			__pmfs_find_data_blocks(sb, pi, blocknr, &bp, 1);
			p = pmfs_get_block(sb, bp);
			pmfs_memunlock_block(sb, p);
		}
		p[j].block_low = cpu_to_le64(i->block_low);
		p[j].block_high = cpu_to_le64(i->block_high);
		j++;

		if (j == 256) {
			j = 0;
			/* Lock the data block */
			pmfs_memlock_block(sb, p);
			pmfs_flush_buffer(p, 4096, false);
		}

		k++;
	}

	/* Lock the block */
	if (j) {
		pmfs_flush_buffer(p, j << 4, false);
		pmfs_memlock_block(sb, p);
	}

	/* 
	 * save the total allocated blocknode mappings 
	 * in super block
	 */
	super = pmfs_get_super(sb);
	pmfs_add_logentry(sb, trans, &super->s_wtime,
			PMFS_FAST_MOUNT_FIELD_SIZE, LE_DATA);

	pmfs_memunlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);

	super->s_wtime = cpu_to_le32(get_seconds());
	super->s_num_blocknode_allocated = 
			cpu_to_le64(sbi->num_blocknode_allocated);
	super->s_num_free_blocks = cpu_to_le64(sbi->num_free_blocks);
	super->s_inodes_count = cpu_to_le32(sbi->s_inodes_count);
	super->s_free_inodes_count = cpu_to_le32(sbi->s_free_inodes_count);
	super->s_inodes_used_count = cpu_to_le32(sbi->s_inodes_used_count);
	super->s_free_inode_hint = cpu_to_le32(sbi->s_free_inode_hint);

	pmfs_memlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);
	/* commit the transaction */
	pmfs_commit_transaction(sb, trans);
#endif
}

static void pmfs_inode_crawl_recursive(struct super_block *sb,
				struct scan_bitmap *bm, unsigned long block,
				u32 height, u8 btype)
{
	__le64 *node;
	unsigned int i;

	if (height == 0) {
		/* This is the data block */
		if (btype == PMFS_BLOCK_TYPE_4K) {
			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
		} else if (btype == PMFS_BLOCK_TYPE_2M) {
			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
		} else {
			set_bit(block >> PAGE_SHIFT_1G, bm->bitmap_1G);
		}
		return;
	}

	node = pmfs_get_block(sb, block);
	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		pmfs_inode_crawl_recursive(sb, bm,
			le64_to_cpu(node[i]), height - 1, btype);
	}
}

static inline void pmfs_inode_crawl(struct super_block *sb,
				struct scan_bitmap *bm, struct pmfs_inode *pi)
{
	if (pi->root == 0)
		return;
	pmfs_inode_crawl_recursive(sb, bm, le64_to_cpu(pi->root), pi->height,
					pi->i_blk_type);
}

static void pmfs_inode_table_crawl_recursive(struct super_block *sb,
				struct scan_bitmap *bm, unsigned long block,
				u32 height, u32 btype)
{
	__le64 *node;
	unsigned int i;
	struct pmfs_inode *pi;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	
	node = pmfs_get_block(sb, block);

	if (height == 0) {
		unsigned int inodes_per_block = INODES_PER_BLOCK(btype);
		if (likely(btype == PMFS_BLOCK_TYPE_2M))
			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
		else
			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

		sbi->s_inodes_count += inodes_per_block;
		for (i = 0; i < inodes_per_block; i++) {
			pi = (struct pmfs_inode *)((void *)node +
                                                        PMFS_INODE_SIZE * i);
			if (le16_to_cpu(pi->i_links_count) == 0 &&
                        	(le16_to_cpu(pi->i_mode) == 0 ||
                         	le32_to_cpu(pi->i_dtime))) {
					/* Empty inode */
					continue;
			}
			sbi->s_inodes_used_count++;
			pmfs_inode_crawl(sb, bm, pi);
		}
		return;
	}

	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		pmfs_inode_table_crawl_recursive(sb, bm,
			le64_to_cpu(node[i]), height - 1, btype);
	}
}
