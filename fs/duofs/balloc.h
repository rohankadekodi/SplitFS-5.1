#ifndef __duofs_BALLOC_H
#define __duofs_BALLOC_H

#include "inode.h"

/* DRAM structure to hold a list of free PMEM blocks */
struct free_list {
	spinlock_t s_lock;
	struct rb_root	unaligned_block_free_tree;
	struct rb_root  huge_aligned_block_free_tree;
	struct duofs_range_node *first_node_unaligned; // lowest address free range
	struct duofs_range_node *first_node_huge_aligned; // lowest address free range

	int		index; // Which CPU do I belong to?

	/* Start and end of allocatable range, inclusive. Excludes csum and
	 * parity blocks.
	 */
	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long	num_free_blocks;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode_unaligned;
	unsigned long   num_blocknode_huge_aligned;

	/* Statistics */
	/*
	unsigned long	alloc_log_count;
	unsigned long	alloc_data_count;
	unsigned long	free_log_count;
	unsigned long	free_data_count;
	unsigned long	alloc_log_pages;
	unsigned long	alloc_data_pages;
	unsigned long	freed_log_pages;
	unsigned long	freed_data_pages;
	*/
	u64		padding[8];	/* Cache line break.
					 * [TODO]: Need to measure this */
};

static inline
struct free_list *duofs_get_free_list(struct super_block *sb, int cpu)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);

	return &sbi->free_lists[cpu];
}

enum node_type {
	NODE_BLOCK=1,
	NODE_INODE,
	NODE_DIR,
};

int duofs_alloc_block_free_lists(struct super_block *sb);
struct duofs_range_node *duofs_alloc_inode_node(struct super_block *sb);
void duofs_delete_free_lists(struct super_block *sb);
struct duofs_range_node *duofs_alloc_dir_node(struct super_block *sb);
struct vma_item *duofs_alloc_vma_item(struct super_block *sb);
void duofs_free_range_node(struct duofs_range_node *node);
void duofs_free_inode_node(struct duofs_range_node *node);
void duofs_free_dir_node(struct duofs_range_node *bnode);
void duofs_free_vma_item(struct super_block *sb,
			struct vma_item *item);
extern int duofs_find_range_node(struct rb_root *tree, unsigned long key,
				enum node_type type,
				struct duofs_range_node **ret_node);
int duofs_search_inodetree(struct duofs_sb_info *sbi,
			  unsigned long ino, struct duofs_range_node **ret_node);
int duofs_insert_inodetree(struct duofs_sb_info *sbi,
			  struct duofs_range_node *new_node, int cpuid);

extern int duofs_insert_range_node(struct rb_root *tree,
				  struct duofs_range_node *new_node,
				  enum node_type type);
void duofs_destroy_range_node_tree(struct super_block *sb,
				  struct rb_root *tree);
int duofs_insert_blocktree(struct rb_root *tree,
			  struct duofs_range_node *new_node);
int duofs_find_free_slot(struct rb_root *tree, unsigned long range_low,
			unsigned long range_high, struct duofs_range_node **prev,
			struct duofs_range_node **next);


#endif
