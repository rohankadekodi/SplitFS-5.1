#ifndef __DUOFS_INODE_H
#define __DUOFS_INODE_H

/*
 * Structure of an inode in duofs. Things to keep in mind when modifying it.
 * 1) Keep the inode size to within 96 bytes if possible. This is because
 *    a 64 byte log-entry can store 48 bytes of data and we would like
 *    to log an inode using only 2 log-entries
 * 2) root must be immediately after the qw containing height because we update
 *    root and height atomically using cmpxchg16b in duofs_decrease_btree_height 
 * 3) i_size, i_ctime, and i_mtime must be in that order and i_size must be at
 *    16 byte aligned offset from the start of the inode. We use cmpxchg16b to
 *    update these three fields atomically.
 */
struct duofs_inode {
	/* first 48 bytes */
	__le16	i_rsvd;         /* reserved. used to be checksum */
	u8	    height;         /* height of data b-tree; max 3 for now */
	u8	    i_blk_type;     /* data block size this inode uses */
	__le32	i_flags;            /* Inode flags */
	__le64	root;               /* btree root. must be below qw w/ height */
	__le64	i_size;             /* Size of data in bytes */
	__le32	i_ctime;            /* Inode modification time */
	__le32	i_mtime;            /* Inode b-tree Modification time */
	__le32	i_dtime;            /* Deletion Time */
	__le16	i_mode;             /* File mode */
	__le16	i_links_count;      /* Links count */
	__le64	i_blocks;           /* Blocks count */

	/* second 48 bytes */
	__le64	i_xattr;            /* Extended attribute block */
	__le32	i_uid;              /* Owner Uid */
	__le32	i_gid;              /* Group Id */
	__le32	i_generation;       /* File version (for NFS) */
	__le32	i_atime;            /* Access time */

	struct {
		__le32 rdev;    /* major/minor # */
	} dev;              /* device inode */
	u8      huge_aligned_file;  /* is the file hugepage aligned */
	u8      numa_node; /* which NUMA node is the file data present in */
	__le32 padding;     /* pad to ensure truncate_item starts 8-byte aligned */
};

/*
 * Inode table. It is a linked list of pages.
 */
struct inode_table {
	__le64 log_head;
};

/*
 * duofs-specific inode state kept in DRAM
 */
struct duofs_inode_info_header {
	struct rb_root rb_tree;         /* RB tree for directory */
	struct rb_root vma_tree;	/* Write vmas */
	int num_vmas;
	unsigned short i_mode;
	unsigned int i_flags;
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	struct duofs_direntry *last_dentry;
	u8 i_blk_type;
};

/* This is a per-inode structure and follows immediately after the 
 * struct duofs_inode. It is used to implement the truncate linked list and is 
 * by duofs_truncate_add(), duofs_truncate_del(), and duofs_recover_truncate_list()
 * functions to manage the truncate list */
struct duofs_inode_truncate_item {
	__le64	i_truncatesize;     /* Size of truncated inode */
	__le64  i_next_truncate;    /* inode num of the next truncated inode */
};

struct duofs_inode_info {
	__u32   i_dir_start_lookup;
	struct list_head i_truncated;
	struct duofs_inode_info_header header;
	struct inode	vfs_inode;
};

static inline unsigned int duofs_inode_blk_shift (struct duofs_inode *pi)
{
	return blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t duofs_inode_blk_size (struct duofs_inode *pi)
{
	return blk_type_to_size[pi->i_blk_type];
}

static inline u64
duofs_get_addr_off(struct duofs_sb_info *sbi, void *addr)
{
	DUOFS_ASSERT(((addr >= sbi->virt_addr) &&
		    (addr < (sbi->virt_addr + sbi->initsize))) ||
		    ((addr >= sbi->virt_addr_2) &&
		     (addr < (sbi->virt_addr_2 + sbi->initsize_2))));
	return (u64)(addr - sbi->virt_addr);
}

static inline unsigned long __duofs_find_data_blocks(struct super_block *sb,
						   struct duofs_inode *pi,
						   unsigned long blocknr,
						   u64 *bp,
						   unsigned long max_blocks)
{
	__le64 *level_ptr;
	u32 height, bit_shift;
	unsigned int idx, cur_idx;
	unsigned long num_contiguous_blocks = 0;
	u64 cur_bp = 0;
	u64 local_bp = 0;

	height = pi->height;
	local_bp = le64_to_cpu(pi->root);

	while (height > 0) {
		level_ptr = duofs_get_block(sb, local_bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;

		local_bp = le64_to_cpu(level_ptr[idx]);
		if (local_bp == 0) {
			*bp = 0;
			return 0;
		}

		if (height == 1) {
			/* Find the contiguous extent */
			cur_bp = local_bp;
			cur_idx = idx;

			while (num_contiguous_blocks < max_blocks &&
			       cur_idx < 512) {
				if (level_ptr[cur_idx] != cur_bp)
					break;

				cur_idx++;
				cur_bp += PAGE_SIZE;
				num_contiguous_blocks++;
			}
		}

		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}

	*bp = local_bp;

	if (num_contiguous_blocks == 0)
		num_contiguous_blocks = 1;

	return num_contiguous_blocks;
}


static inline struct inode_table *duofs_get_inode_table_log(struct super_block *sb,
	int cpu)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	int table_start;

	if (cpu >= sbi->cpus)
		return NULL;

	table_start = INODE_TABLE0_START;

	return (struct inode_table *)((char *)
				      duofs_get_block(sb,
						      DUOFS_DEF_BLOCK_SIZE_4K *
						      table_start) +
				      cpu * CACHELINE_SIZE);
}

/* Get the address in PMEM of an inode by inode number. Allocate additional
 * block to store additional inodes if necessary.
 */
static inline struct duofs_inode *duofs_get_inode(struct super_block *sb, u64 ino)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct inode_table *inode_table;
	unsigned int data_bits;
	unsigned int num_inodes_bits;
	struct duofs_inode *duofs_inode_table = duofs_get_inode_table(sb);
	u64 curr;
	unsigned int superpage_count;
	u64 internal_ino;
	int cpuid;
	unsigned int index;
	unsigned int i = 0;
	unsigned long blocknr;
	unsigned long curr_addr;
	int allocated;

	if (ino > DUOFS_BLOCKNODE_IN0 && ino < DUOFS_NORMAL_INODE_START)
		return NULL;

	data_bits = blk_type_to_shift[duofs_inode_table->i_blk_type];
	num_inodes_bits = data_bits - DUOFS_INODE_BITS;

	cpuid = ino % sbi->cpus;
	internal_ino = ino / sbi->cpus;

	inode_table = duofs_get_inode_table_log(sb, cpuid);
	superpage_count = internal_ino >> num_inodes_bits;
	index = internal_ino & ((1 << num_inodes_bits) - 1);

	curr = inode_table->log_head;

	duofs_dbg_verbose("%s: cpuid = %d. ino = %llu. internal_ino = %llu. inode_table = 0x%p. superpage_count = %u. index = %u. curr = %llu log_head addr = 0x%p\n", __func__, cpuid, ino, internal_ino, inode_table, superpage_count, index, curr, &(inode_table->log_head));

	if (curr == 0) {
		duofs_dbg("%s: could not find inode for ino = %llu\n",
				 __func__, ino);
		return NULL;
	}

	for (i = 0; i < superpage_count; i++) {
		if (curr == 0) {
			duofs_dbg("%s: could not get the inode log for super page = %d\n",
					 __func__, i);
			return NULL;
		}

		curr_addr = (unsigned long) duofs_get_block(sb, curr);
		/* Next page pointer in the last 8 bytes of the superpage */
		curr_addr += blk_type_to_size[duofs_inode_table->i_blk_type] - 8;
		curr = *(u64 *)(curr_addr);

		if (curr == 0) {
			allocated = duofs_new_blocks(sb, &blocknr, 1,
						    DUOFS_BLOCK_TYPE_2M,
						    1, cpuid);

			if (allocated != 1) {
				duofs_dbg("%s: could not extend inode table for cpu = %d\n",
						 __func__, cpuid);
				return NULL;
			}

			duofs_dbg("%s: extended inode table for cpu = %d\n",
					 __func__, cpuid);


			curr = duofs_get_block_off(sb, blocknr,
						  DUOFS_BLOCK_TYPE_2M);
			duofs_memunlock_range(sb, (void *)curr_addr,
					     CACHELINE_SIZE);
			*(u64 *)(curr_addr) = curr;
			duofs_memlock_range(sb, (void *)curr_addr,
					   CACHELINE_SIZE);
			duofs_flush_buffer((void *)curr_addr,
					  DUOFS_INODE_SIZE, 1);
		}
	}

	//duofs_dbg_verbose("%s: Found the duofs inode for ino = %llu\n",
	//		 __func__, ino);

	curr = (u64)duofs_get_block(sb, curr);
	return (struct duofs_inode *)(curr + index * DUOFS_INODE_SIZE);
}

/* If this is part of a read-modify-write of the inode metadata,
 * duofs_memunlock_inode() before calling! */
/*
static inline struct duofs_inode *duofs_get_inode(struct super_block *sb,
						  u64	ino)
{
	struct duofs_super_block *ps = duofs_get_super(sb);
	struct duofs_inode *inode_table = duofs_get_inode_table(sb);
	u64 bp, block, ino_offset;

	if (ino == 0)
		return NULL;

	block = ino >> duofs_inode_blk_shift(inode_table);
	bp = __duofs_find_data_block(sb, inode_table, block);

	if (bp == 0)
		return NULL;
	ino_offset = (ino & (duofs_inode_blk_size(inode_table) - 1));
	return (struct duofs_inode *)((void *)ps + bp + ino_offset);
}
*/


static inline struct duofs_inode_info *DUOFS_I(struct inode *inode)
{
	return container_of(inode, struct duofs_inode_info, vfs_inode);
}

static inline struct duofs_inode_truncate_item * duofs_get_truncate_item (struct 
		super_block *sb, u64 ino)
{
	struct duofs_inode *pi = duofs_get_inode(sb, ino);
	return (struct duofs_inode_truncate_item *)(pi + 1);
}

static inline struct duofs_inode_truncate_item * duofs_get_truncate_list_head (
		struct super_block *sb)
{
	struct duofs_inode *pi = duofs_get_inode_table(sb);
	return (struct duofs_inode_truncate_item *)(pi + 1);
}

static inline void check_eof_blocks(struct super_block *sb, 
		struct duofs_inode *pi, loff_t size)
{
	if ((pi->i_flags & cpu_to_le32(DUOFS_EOFBLOCKS_FL)) &&
		(size + sb->s_blocksize) > (le64_to_cpu(pi->i_blocks)
			<< sb->s_blocksize_bits))
		pi->i_flags &= cpu_to_le32(~DUOFS_EOFBLOCKS_FL);
}

static inline void duofs_update_time_and_size(struct inode *inode,
	struct duofs_inode *pi)
{
	__le32 words[2];
	__le64 new_pi_size = cpu_to_le64(i_size_read(inode));

	/* pi->i_size, pi->i_ctime, and pi->i_mtime need to be atomically updated.
 	* So use cmpxchg16b here. */
	words[0] = cpu_to_le32(inode->i_ctime.tv_sec);
	words[1] = cpu_to_le32(inode->i_mtime.tv_sec);
	/* TODO: the following function assumes cmpxchg16b instruction writes
 	* 16 bytes atomically. Confirm if it is really true. */
	cmpxchg_double_local(&pi->i_size, (u64 *)&pi->i_ctime, pi->i_size,
		*(u64 *)&pi->i_ctime, new_pi_size, *(u64 *)words);
}

int duofs_init_inode_inuse_list(struct super_block *sb);
extern unsigned int duofs_free_inode_subtree(struct super_block *sb,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr);
extern int __duofs_alloc_blocks(duofs_transaction_t *trans,
			       struct super_block *sb, struct duofs_inode *pi,
			       unsigned long file_blocknr,
			       unsigned int num, bool zero, int cpu, int write_path,
			       __le64 *free_blk_list, unsigned long *num_free_blks,
			       void **log_entries, __le64 *log_entry_nums, int *log_entry_idx);
extern int __duofs_alloc_blocks_wrapper(duofs_transaction_t *trans,
				       struct super_block *sb,
				       struct duofs_inode *pi,
				       unsigned long file_blocknr,
				       unsigned int num, bool zero,
				       int cpu, int write_path);
int truncate_strong_guarantees(struct super_block *sb, __le64 *node,
			       unsigned long num_blocks, u32 btype);
extern int duofs_init_inode_table(struct super_block *sb);
extern int duofs_alloc_blocks(duofs_transaction_t *trans, struct inode *inode,
			     unsigned long file_blocknr, unsigned int num,
			     bool zero, int cpu, int write_path, __le64 *free_blk_list,
			     unsigned long *num_free_blks, void **log_entries,
			     __le64 *log_entry_nums, int *log_entry_idx);
extern int duofs_alloc_blocks_weak(duofs_transaction_t *trans, struct inode *inode,
				  unsigned long file_blocknr, unsigned int num,
				  bool zero, int cpu, int write_path);
extern unsigned long duofs_find_data_blocks(struct inode *inode,
				 unsigned long file_blocknr,
				 u64 *bp,
				 unsigned long max_blocks);
int duofs_set_blocksize_hint(struct super_block *sb, struct duofs_inode *pi,
		loff_t new_size);
void duofs_setsize(struct inode *inode, loff_t newsize);

extern struct inode *duofs_iget(struct super_block *sb, unsigned long ino);
extern void duofs_put_inode(struct inode *inode);
extern void duofs_evict_inode(struct inode *inode);
extern struct inode *duofs_new_inode(duofs_transaction_t *trans,
	struct inode *dir, umode_t mode, const struct qstr *qstr);
extern void duofs_update_isize(struct inode *inode, struct duofs_inode *pi);
extern void duofs_update_nlink(struct inode *inode, struct duofs_inode *pi);
extern void duofs_update_time(struct inode *inode, struct duofs_inode *pi);
extern int duofs_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void duofs_dirty_inode(struct inode *inode, int flags);
extern int duofs_notify_change(struct dentry *dentry, struct iattr *attr);
int duofs_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int flags);
extern void duofs_set_inode_flags(struct inode *inode, struct duofs_inode *pi);
extern void duofs_get_inode_flags(struct inode *inode, struct duofs_inode *pi);
extern unsigned long duofs_find_region(struct inode *inode, loff_t *offset,
		int hole);
extern void duofs_truncate_del(struct inode *inode);
extern void duofs_truncate_add(struct inode *inode, u64 truncate_size);


#endif
