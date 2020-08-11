/*
 * BRIEF DESCRIPTION
 *
 * XIP operations.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include "duofs.h"
#include "xip.h"
#include "inode.h"

static ssize_t
do_xip_mapping_read(struct address_space *mapping,
		    struct file_ra_state *_ra,
		    struct file *filp,
		    char __user *buf,
		    size_t len,
		    loff_t *ppos)
{
	struct inode *inode = mapping->host;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;
	loff_t start_pos = *ppos;
	loff_t end_pos = start_pos + len - 1;
	unsigned long start_block = start_pos >> PAGE_SHIFT;
	unsigned long end_block = end_pos >> PAGE_SHIFT;
	unsigned long num_blocks = end_block - start_block + 1;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;
	do {
		unsigned long nr, left;
		void *xip_mem;
		unsigned long xip_pfn;
		int zero = 0;
		int blocks_found;

		blocks_found = duofs_get_xip_mem(mapping, index, num_blocks, 0,
						&xip_mem, &xip_pfn);

		if (unlikely(blocks_found <= 0)) {
			if (blocks_found == -ENODATA || blocks_found == 0) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		if (blocks_found == 0) {
			nr = PAGE_SIZE;
			if (index >= end_index) {
				if (index > end_index)
					goto out;
				nr = ((isize - 1) & ~PAGE_MASK) + 1;
				if (nr <= offset)
					goto out;
			}
		} else {
			if (index + blocks_found - 1 >= end_index) {
				if (index > end_index)
					goto out;

				nr = ((isize - 1) & ~PAGE_MASK) + 1;
				nr += (end_index - index) * PAGE_SIZE;
				if (nr <= offset) {
					goto out;
				}
			} else
				nr = PAGE_SIZE*blocks_found;
		}

		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			/* address based flush */ ;

		/*
		 * Ok, we have the mem, so now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		DUOFS_START_TIMING(memcpy_r_t, memcpy_time);
		if (!zero)
			left = __copy_to_user(buf+copied, xip_mem+offset, nr);
		else
			left = __clear_user(buf + copied, nr);
		DUOFS_END_TIMING(memcpy_r_t, memcpy_time);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		num_blocks -= offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

ssize_t
xip_file_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	if (!access_ok(buf, len))
		return -EFAULT;

	return do_xip_mapping_read(filp->f_mapping, &filp->f_ra, filp,
				   buf, len, ppos);
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * i_mutex.
 */
ssize_t duofs_xip_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	ssize_t res;
	timing_t xip_read_time;

	DUOFS_START_TIMING(xip_read_t, xip_read_time);
//	rcu_read_lock();
	res = xip_file_read(filp, buf, len, ppos);
//	rcu_read_unlock();
	DUOFS_END_TIMING(xip_read_t, xip_read_time);
	return res;
}

static inline void duofs_flush_edge_cachelines(loff_t pos, ssize_t len,
	void *start_addr)
{
	if (unlikely(pos & 0x7))
		duofs_flush_buffer(start_addr, 1, false);
	if (unlikely(((pos + len) & 0x7) && ((pos & (CACHELINE_SIZE - 1)) !=
			((pos + len) & (CACHELINE_SIZE - 1)))))
		duofs_flush_buffer(start_addr + len, 1, false);
}

static inline size_t memcpy_to_nvmm(char *kmem, loff_t offset,
	const char __user *buf, size_t bytes)
{
	size_t copied;

	copied = bytes - __copy_from_user_inatomic_nocache(kmem +
							   offset, buf, bytes);

	return copied;
}

static ssize_t
__duofs_xip_file_write(struct address_space *mapping, const char __user *buf,
          size_t count, loff_t pos, loff_t *ppos)
{
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	long        status = 0;
	size_t      bytes;
	ssize_t     written = 0;
	struct duofs_inode *pi;
	timing_t memcpy_time, write_time;
	loff_t start_pos = pos;
	loff_t end_pos = start_pos + count - 1;
	unsigned long start_block = start_pos >> sb->s_blocksize_bits;
	unsigned long end_block = end_pos >> sb->s_blocksize_bits;

	DUOFS_START_TIMING(internal_write_t, write_time);
	pi = duofs_get_inode(sb, inode->i_ino);
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xmem;
		unsigned long xpfn;
		int blocks_found;
		unsigned long num_blocks;

		index = pos >> sb->s_blocksize_bits;
		num_blocks = end_block - index + 1;

		blocks_found = duofs_get_xip_mem(mapping, index,
						num_blocks, 1,
						&xmem, &xpfn);
		if (blocks_found <= 0) {
			break;
		}

		offset = (pos & (sb->s_blocksize - 1)); /* Within page */
		bytes = (sb->s_blocksize*blocks_found) - offset;
		if (bytes > count)
			bytes = count;


		DUOFS_START_TIMING(memcpy_w_t, memcpy_time);
		duofs_xip_mem_protect(sb, xmem + offset, bytes, 1);
		copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
		duofs_xip_mem_protect(sb, xmem + offset, bytes, 0);
		DUOFS_END_TIMING(memcpy_w_t, memcpy_time);

		/* if start or end dest address is not 8 byte aligned, 
	 	 * __copy_from_user_inatomic_nocache uses cacheable instructions
	 	 * (instead of movnti) to write. So flush those cachelines. */
		duofs_flush_edge_cachelines(pos, copied, xmem + offset);

        	if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);
	*ppos = pos;
	/*
 	* No need to use i_size_read() here, the i_size
 	* cannot change under us because we hold i_mutex.
 	*/
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		duofs_update_isize(inode, pi);
	}

	DUOFS_END_TIMING(internal_write_t, write_time);
	return written ? written : status;
}

/* optimized path for file write that doesn't require a transaction. In this
 * path we don't need to allocate any new data blocks. So the only meta-data
 * modified in path is inode's i_size, i_ctime, and i_mtime fields */
static ssize_t duofs_file_write_fast(struct super_block *sb, struct inode *inode,
	struct duofs_inode *pi, const char __user *buf, size_t count, loff_t pos,
	loff_t *ppos, u64 block)
{
	void *xmem = duofs_get_block(sb, block);
	size_t copied, ret = 0, offset;
	timing_t memcpy_time;

	offset = pos & (sb->s_blocksize - 1);

	DUOFS_START_TIMING(memcpy_w_t, memcpy_time);
	duofs_xip_mem_protect(sb, xmem + offset, count, 1);
	copied = memcpy_to_nvmm((char *)xmem, offset, buf, count);
	duofs_xip_mem_protect(sb, xmem + offset, count, 0);
	DUOFS_END_TIMING(memcpy_w_t, memcpy_time);

	duofs_flush_edge_cachelines(pos, copied, xmem + offset);

	if (likely(copied > 0)) {
		pos += copied;
		ret = copied;
	}
	if (unlikely(copied != count && copied == 0))
		ret = -EFAULT;
	*ppos = pos;
	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (pos > inode->i_size) {
		/* make sure written data is persistent before updating
	 	* time and size */
		PERSISTENT_MARK();
		i_size_write(inode, pos);
		PERSISTENT_BARRIER();
		duofs_memunlock_inode(sb, pi);
		duofs_update_time_and_size(inode, pi);
		duofs_memlock_inode(sb, pi);
	} else {
		u64 c_m_time;
		/* update c_time and m_time atomically. We don't need to make the data
		 * persistent because the expectation is that the close() or an explicit
		 * fsync will do that. */
		c_m_time = (inode->i_ctime.tv_sec & 0xFFFFFFFF);
		c_m_time = c_m_time | (c_m_time << 32);
		duofs_memunlock_inode(sb, pi);
		duofs_memcpy_atomic(&pi->i_ctime, &c_m_time, 8);
		duofs_memlock_inode(sb, pi);
	}
	duofs_flush_buffer(pi, 1, false);
	return ret;
}

/*
 * blk_off is used in different ways depending on whether the edge block is
 * at the beginning or end of the write. If it is at the beginning, we copy from
 * start-of-block to 'blk_off'. If it is the end block, we copy from 'blk_off' to
 * end-of-block
 */
static inline void duofs_copy_to_edge_blk (struct super_block *sb, struct
				       duofs_inode *pi, bool over_blk, unsigned long block, size_t blk_off,
				       bool is_end_blk, void *buf)
{
	void *ptr;
	size_t count;
	unsigned long blknr;
	u64 bp = 0;

	if (over_blk) {
		blknr = block >> (duofs_inode_blk_shift(pi) -
			sb->s_blocksize_bits);
		__duofs_find_data_blocks(sb, pi, blknr, &bp, 1);
		ptr = duofs_get_block(sb, bp);
		if (ptr != NULL) {
			if (is_end_blk) {
				ptr = ptr + blk_off - (blk_off % 8);
				count = duofs_inode_blk_size(pi) -
					blk_off + (blk_off % 8);
			} else
				count = blk_off + (8 - (blk_off % 8));

			duofs_memunlock_range(sb, ptr,  duofs_inode_blk_size(pi));
			memcpy_to_nvmm(ptr, 0, buf, count);
			duofs_memlock_range(sb, ptr,  duofs_inode_blk_size(pi));
		}
	}
}

/*
 * blk_off is used in different ways depending on whether the edge block is
 * at the beginning or end of the write. If it is at the beginning, we copy from
 * start-of-block to 'blk_off'. If it is the end block, we copy from 'blk_off' to
 * end-of-block
 */
static inline void duofs_copy_from_edge_blk (struct super_block *sb, struct
				       duofs_inode *pi, bool over_blk, unsigned long block, size_t blk_off,
				       bool is_end_blk, void **buf)
{
	void *ptr;
	size_t count;
	unsigned long blknr;
	u64 bp = 0;

	if (over_blk) {
		blknr = block >> (duofs_inode_blk_shift(pi) -
			sb->s_blocksize_bits);
		__duofs_find_data_blocks(sb, pi, blknr, &bp, 1);
		ptr = duofs_get_block(sb, bp);
		if (ptr != NULL) {
			if (is_end_blk) {
				ptr = ptr + blk_off - (blk_off % 8);
				count = duofs_inode_blk_size(pi) -
					blk_off + (blk_off % 8);
			} else
				count = blk_off + (8 - (blk_off % 8));

			*buf = kmalloc(count, GFP_KERNEL);
			duofs_memunlock_range(sb, ptr,  duofs_inode_blk_size(pi));
			__copy_to_user(*buf, ptr, count);
			duofs_memlock_range(sb, ptr,  duofs_inode_blk_size(pi));
		}
	}
}

/*
 * blk_off is used in different ways depending on whether the edge block is
 * at the beginning or end of the write. If it is at the beginning, we zero from
 * start-of-block to 'blk_off'. If it is the end block, we zero from 'blk_off' to
 * end-of-block
 */
static inline void duofs_clear_edge_blk (struct super_block *sb, struct
	duofs_inode *pi, bool new_blk, unsigned long block, size_t blk_off,
	bool is_end_blk)
{
	void *ptr;
	size_t count;
	unsigned long blknr;
	u64 bp = 0;

	if (new_blk) {
		blknr = block >> (duofs_inode_blk_shift(pi) -
			sb->s_blocksize_bits);
		__duofs_find_data_blocks(sb, pi, blknr, &bp, 1);
		ptr = duofs_get_block(sb, bp);
		if (ptr != NULL) {
			if (is_end_blk) {
				ptr = ptr + blk_off - (blk_off % 8);
				count = duofs_inode_blk_size(pi) -
					blk_off + (blk_off % 8);
			} else
				count = blk_off + (8 - (blk_off % 8));
			duofs_memunlock_range(sb, ptr,  duofs_inode_blk_size(pi));
			memset_nt(ptr, 0, count);
			duofs_memlock_range(sb, ptr,  duofs_inode_blk_size(pi));
		}
	}
}

ssize_t duofs_xip_cow_file_write(struct file *filp, const char __user *buf,
          size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	duofs_transaction_t *trans;
	struct duofs_inode *pi;
	ssize_t     written = 0;
	loff_t pos;
	u64 block;
	bool new_sblk = false, new_eblk = false;
	bool over_sblk = false, over_eblk = false;
	size_t count, offset, eblk_offset, ret;
	unsigned long start_blk, end_blk, num_blocks, max_logentries;
	bool same_block;
	timing_t xip_write_time, xip_write_fast_time;
	int num_blocks_found = 0;
	void *start_buf = NULL, *end_buf = NULL;
	__le64 *free_blk_list = NULL;
	__le64 *inplace_blk_list = NULL;
	__le64 **log_entries = NULL;
	__le64 *log_entry_nums = NULL;
	unsigned long num_inplace_blks = 0;
	int log_entry_idx = 0;
	int idx = 0, idx2 = 0;
	int free_blk_list_idx = 0;
	__le64 block_val = 0;

	DUOFS_START_TIMING(xip_write_t, xip_write_time);

	sb_start_write(inode->i_sb);
	inode_lock(inode);

	if (!access_ok(buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;
	if (count == 0) {
		ret = 0;
		goto out;
	}

	pi = duofs_get_inode(sb, inode->i_ino);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (duofs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	num_blocks_found = duofs_find_data_blocks(inode, start_blk, &block, 1);

	/* Referring to the inode's block size, not 4K */
	same_block = (((count + offset - 1) >>
			duofs_inode_blk_shift(pi)) == 0) ? 1 : 0;
	if (block && same_block) {
		DUOFS_START_TIMING(xip_write_fast_t, xip_write_fast_time);
		ret = duofs_file_write_fast(sb, inode, pi, buf, count, pos,
			ppos, block);
		DUOFS_END_TIMING(xip_write_fast_t, xip_write_fast_time);
		goto out;
	}
	max_logentries = num_blocks / MAX_PTRS_PER_LENTRY + 2;
	if (max_logentries > MAX_METABLOCK_LENTRIES)
		max_logentries = MAX_METABLOCK_LENTRIES;

	trans = duofs_new_transaction(sb, MAX_INODE_LENTRIES + max_logentries);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}
	duofs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	ret = file_remove_privs(filp);
	if (ret) {
		duofs_abort_transaction(sb, trans);
		goto out;
	}
	inode->i_ctime = inode->i_mtime = current_time(inode);
	duofs_update_time(inode, pi);

	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	if (offset != 0) {
		duofs_find_data_blocks(inode, start_blk, &block, 1);
		if (block == 0)
			new_sblk = true;
		else if (pos < i_size_read(inode))
			over_sblk = true;
	}

	eblk_offset = (pos + count) & (duofs_inode_blk_size(pi) - 1);
	if (eblk_offset != 0) {
		duofs_find_data_blocks(inode, end_blk, &block, 1);
		if (block == 0)
			new_eblk = true;
		else if ((pos + count) < i_size_read(inode))
			over_eblk = true;
	}

	duofs_copy_from_edge_blk(sb, pi, over_sblk, start_blk, offset, false, &start_buf);
	duofs_copy_from_edge_blk(sb, pi, over_eblk, end_blk, eblk_offset, true, &end_buf);

	inplace_blk_list = (__le64 *) kmalloc(num_blocks * sizeof(__le64), GFP_KERNEL);
	free_blk_list = (__le64 *) kmalloc(num_blocks * sizeof(__le64), GFP_KERNEL);
	log_entries = (__le64 **) kmalloc(num_blocks * sizeof(__le64), GFP_KERNEL);
	log_entry_nums = (__le64 *) kmalloc(num_blocks * sizeof(__le64), GFP_KERNEL);

	num_inplace_blks = 0;

	/* don't zero-out the allocated blocks */
	duofs_alloc_blocks(trans, inode, start_blk, num_blocks, false,
			  ANY_CPU, 1, inplace_blk_list, &num_inplace_blks,
			  (void **)log_entries, log_entry_nums, &log_entry_idx);

	/* now zero out the edge blocks which will be partially written */
	duofs_clear_edge_blk(sb, pi, new_sblk, start_blk, offset, false);
	duofs_clear_edge_blk(sb, pi, new_eblk, end_blk, eblk_offset, true);

	duofs_copy_to_edge_blk(sb, pi, over_sblk, start_blk, offset, false, start_buf);
	duofs_copy_to_edge_blk(sb, pi, over_eblk, end_blk, eblk_offset, true, end_buf);

	if (start_buf)
		kfree(start_buf);
	if (end_buf)
		kfree(end_buf);
	start_buf = NULL;
	end_buf = NULL;

	written = __duofs_xip_file_write(mapping, buf, count, pos, ppos);
	if (written < 0 || written != count)
		duofs_dbg_verbose("write incomplete/failed: written %ld len %ld"
				 " pos %llx start_blk %lx num_blocks %lx\n",
				 written, count, pos, start_blk, num_blocks);

	duofs_commit_transaction(sb, trans);

	if (num_inplace_blks > 0) {
		trans = duofs_new_transaction(sb, max_logentries);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out;
		}

		free_blk_list_idx = 0;
		for (idx = 0; idx < log_entry_idx; idx++) {
			duofs_add_logentry(sb, trans, (void *)log_entries[idx],
					  (size_t)log_entry_nums[idx] << 3, LE_DATA);

			for (idx2 = 0; idx2 < log_entry_nums[idx]; idx2++) {
				block_val = *(log_entries[idx] + (idx2));
				if (block_val != 0) {
					free_blk_list[free_blk_list_idx] = block_val;
					*(log_entries[idx] + (idx2)) = inplace_blk_list[free_blk_list_idx];
					free_blk_list_idx++;
				}
			}
		}

		written = __duofs_xip_file_write(mapping, buf, count, pos, ppos);
		if (written < 0 || written != count)
			duofs_dbg_verbose("write incomplete/failed: written %ld len %ld"
					 " pos %llx start_blk %lx num_blocks %lx\n",
					 written, count, pos, start_blk, num_blocks);

		duofs_commit_transaction(sb, trans);

		if (free_blk_list != NULL && num_inplace_blks != 0) {
			truncate_strong_guarantees(sb, free_blk_list,
						   free_blk_list_idx,
						   pi->i_blk_type);
			kfree(free_blk_list);
			kfree(log_entries);
			kfree(log_entry_nums);
			kfree(inplace_blk_list);
			free_blk_list = NULL;
			num_inplace_blks = 0;
			log_entry_idx = 0;
		}
	}

	ret = written;
out:
	inode_unlock(inode);
	sb_end_write(inode->i_sb);
	DUOFS_END_TIMING(xip_write_t, xip_write_time);

	return ret;
}


ssize_t duofs_xip_file_write(struct file *filp, const char __user *buf,
          size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	duofs_transaction_t *trans;
	struct duofs_inode *pi;
	ssize_t     written = 0;
	loff_t pos;
	u64 block;
	bool new_sblk = false, new_eblk = false;
	size_t count, offset, eblk_offset, ret;
	unsigned long start_blk, end_blk, num_blocks, max_logentries;
	bool same_block;
	timing_t xip_write_time, xip_write_fast_time;
	int num_blocks_found = 0;
	bool strong_guarantees = DUOFS_SB(sb)->s_mount_opt & DUOFS_MOUNT_STRICT;
	void *start_buf = NULL, *end_buf = NULL;
	__le64 *free_blk_list = NULL;
	unsigned long num_free_blks = 0;
	struct process_numa *proc_numa;
	int cpu = duofs_get_cpuid(sb);
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	bool over_sblk = false, over_eblk = false;

	DUOFS_START_TIMING(xip_write_t, xip_write_time);

	sb_start_write(inode->i_sb);
	inode_lock(inode);

	if (!access_ok(buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;
	if (count == 0) {
		ret = 0;
		goto out;
	}

	pi = duofs_get_inode(sb, inode->i_ino);

	if (sbi->num_numa_nodes > 1 && pi->numa_node != duofs_get_numa_node(sb, cpu)) {
		proc_numa = &(sbi->process_numa[current->tgid % sbi->num_parallel_procs]);
		if (proc_numa->tgid == current->tgid)
			proc_numa->numa_node = pi->numa_node;
		else {
			proc_numa->tgid = current->tgid;
			proc_numa->numa_node = pi->numa_node;
		}

		sched_setaffinity(current->pid, &(sbi->numa_cpus[pi->numa_node].cpumask));
	}

	if (strong_guarantees && pi->huge_aligned_file && pos < i_size_read(inode)) {
		inode_unlock(inode);
		sb_end_write(inode->i_sb);
		return duofs_xip_cow_file_write(filp, buf, len, ppos);
	}

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (duofs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	num_blocks_found = duofs_find_data_blocks(inode, start_blk, &block, 1);

	/* Referring to the inode's block size, not 4K */
	same_block = (((count + offset - 1) >>
			duofs_inode_blk_shift(pi)) == 0) ? 1 : 0;
	if (block && same_block) {
		DUOFS_START_TIMING(xip_write_fast_t, xip_write_fast_time);
		ret = duofs_file_write_fast(sb, inode, pi, buf, count, pos,
			ppos, block);
		DUOFS_END_TIMING(xip_write_fast_t, xip_write_fast_time);
		goto out;
	}
	max_logentries = num_blocks / MAX_PTRS_PER_LENTRY + 2;
	if (max_logentries > MAX_METABLOCK_LENTRIES)
		max_logentries = MAX_METABLOCK_LENTRIES;

	trans = duofs_new_transaction(sb, MAX_INODE_LENTRIES + max_logentries);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}
	duofs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	ret = file_remove_privs(filp);
	if (ret) {
		duofs_abort_transaction(sb, trans);
		goto out;
	}
	inode->i_ctime = inode->i_mtime = current_time(inode);
	duofs_update_time(inode, pi);

	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	if (offset != 0) {
		duofs_find_data_blocks(inode, start_blk, &block, 1);
		if (block == 0)
			new_sblk = true;
		else if (pos < i_size_read(inode))
			over_sblk = true;
	}

	eblk_offset = (pos + count) & (duofs_inode_blk_size(pi) - 1);
	if (eblk_offset != 0) {
		duofs_find_data_blocks(inode, end_blk, &block, 1);
		if (block == 0)
			new_eblk = true;
		else if ((pos + count) < i_size_read(inode))
			over_eblk = true;
	}

	if (strong_guarantees && pos < i_size_read(inode)) {
		duofs_copy_from_edge_blk(sb, pi, over_sblk, start_blk, offset, false, &start_buf);
		duofs_copy_from_edge_blk(sb, pi, over_eblk, end_blk, eblk_offset, true, &end_buf);

		free_blk_list = (__le64 *) kmalloc(num_blocks * sizeof(__le64), GFP_KERNEL);
		num_free_blks = 0;
	}

	/* don't zero-out the allocated blocks */
	duofs_alloc_blocks(trans, inode, start_blk, num_blocks, false,
			  ANY_CPU, 1, free_blk_list, &num_free_blks,
			  NULL, NULL, NULL);

	/* now zero out the edge blocks which will be partially written */
	duofs_clear_edge_blk(sb, pi, new_sblk, start_blk, offset, false);
	duofs_clear_edge_blk(sb, pi, new_eblk, end_blk, eblk_offset, true);

	if (strong_guarantees && pos < i_size_read(inode)) {
		duofs_copy_to_edge_blk(sb, pi, over_sblk, start_blk, offset, false, start_buf);
		duofs_copy_to_edge_blk(sb, pi, over_eblk, end_blk, eblk_offset, true, end_buf);

		if (start_buf)
			kfree(start_buf);
		if (end_buf)
			kfree(end_buf);
		start_buf = NULL;
		end_buf = NULL;
	}

	written = __duofs_xip_file_write(mapping, buf, count, pos, ppos);
	if (written < 0 || written != count)
		duofs_dbg_verbose("write incomplete/failed: written %ld len %ld"
				 " pos %llx start_blk %lx num_blocks %lx\n",
				 written, count, pos, start_blk, num_blocks);

	duofs_commit_transaction(sb, trans);

	if (free_blk_list != NULL && num_free_blks != 0) {
		truncate_strong_guarantees(sb, free_blk_list, num_free_blks, pi->i_blk_type);
		kfree(free_blk_list);
		free_blk_list = NULL;
		num_free_blks = 0;
	}

	ret = written;
out:
	inode_unlock(inode);
	sb_end_write(inode->i_sb);
	DUOFS_END_TIMING(xip_write_t, xip_write_time);

	return ret;
}

static int duofs_find_and_alloc_blocks(struct inode *inode,
				      sector_t iblock,
				      unsigned long max_blocks,
				      u64 *bno,
				      int create)
{
	int err = -EIO;
	u64 block;
	duofs_transaction_t *trans;
	struct duofs_inode *pi;
	int blocks_found = 0;

	blocks_found = duofs_find_data_blocks(inode,
					     iblock, &block,
					     max_blocks);

	if (blocks_found == 0) {
		struct super_block *sb = inode->i_sb;
		if (!create) {
			err = -ENODATA;
			goto err;
		}

		pi = duofs_get_inode(sb, inode->i_ino);
		trans = duofs_current_transaction();
		if (trans) {
			err = duofs_alloc_blocks_weak(trans, inode,
						     iblock,
						     max_blocks,
						     true, ANY_CPU, 0);

			if (err) {
				duofs_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		} else {
			/* 1 lentry for inode, 1 lentry for inode's b-tree */
			trans = duofs_new_transaction(sb, MAX_INODE_LENTRIES);
			if (IS_ERR(trans)) {
				err = PTR_ERR(trans);
				goto err;
			}

			rcu_read_unlock();
			inode_lock(inode);

			duofs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY,
					  LE_DATA);
			err = duofs_alloc_blocks_weak(trans, inode,
						     iblock,
						     max_blocks,
						     true, ANY_CPU, 0);

			duofs_commit_transaction(sb, trans);

			inode_unlock(inode);
			rcu_read_lock();
			if (err) {
				duofs_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		}

		blocks_found = duofs_find_data_blocks(inode, iblock, &block, max_blocks);

		if (blocks_found == 0) {
			duofs_dbg_verbose("[%s:%d] But alloc didn't fail!\n",
				  __func__, __LINE__);
			err = -ENODATA;
			goto err;
		}
	}

	duofs_dbg_verbose("iblock 0x%lx allocated_block 0x%llx\n", iblock,
			 block);

 set_block:
	*bno = block;
	err = 0;
 err:
	return blocks_found;
}

/* OOM err return with xip file fault handlers doesn't mean anything.
 * It would just cause the OS to go an unnecessary killing spree !
 */
static int __duofs_xip_file_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *xip_mem;
	unsigned long xip_pfn;
	int err;

	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		duofs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address, size);
		return VM_FAULT_SIGBUS;
	}

	err = duofs_get_xip_mem(mapping, vmf->pgoff, 1, 1, &xip_mem, &xip_pfn);
	if (unlikely(err < 0)) {
		duofs_dbg("[%s:%d] get_xip_mem failed(OOM). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address);
		return VM_FAULT_SIGBUS;
	}

	duofs_dbg_mmapv("[%s:%d] vm_start(0x%lx), vm_end(0x%lx), pgoff(0x%lx), "
			"BlockSz(0x%lx), VA(0x%lx)->PA(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end, vmf->pgoff,
			PAGE_SIZE, (unsigned long)vmf->address,
			(unsigned long)xip_pfn << PAGE_SHIFT);

	err = vmf_insert_mixed(vma, (unsigned long)vmf->address,
			pfn_to_pfn_t(xip_pfn));

	if (err == -ENOMEM)
		return VM_FAULT_SIGBUS;
	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);
	return VM_FAULT_NOPAGE;
}

int duofs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
	unsigned int flags, struct iomap *iomap, bool taking_lock)
{
	struct duofs_sb_info *sbi = DUOFS_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	bool new = false, boundary = false;
	u64 bno;
	int ret;
	unsigned long diff_between_devs, byte_offset_in_dax;
	unsigned long first_virt_end, second_virt_start;

	duofs_dbg_verbose("%s: calling find_and_alloc_blocks. first_block = %lu "
			 "max_blocks = %lu. length = %lld\n", __func__,
			 first_block, max_blocks, length);

	ret = duofs_find_and_alloc_blocks(inode,
				   first_block,
				   max_blocks,
				   &bno,
				   flags & IOMAP_WRITE);

	if (ret <= 0) {
		duofs_dbg("%s: duofs_dax_get_blocks failed %d", __func__, ret);
		duofs_dbg("%s: returning %d\n", __func__, ret);
		return ret;
	}

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->dax_dev = sbi->s_dax_dev;
	iomap->offset = (u64)first_block << blkbits;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->offset = IOMAP_NULL_ADDR;
		iomap->length = 1 << blkbits;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->offset = (sector_t)(bno >> 9);//<< (blkbits - 9));
		iomap->length = (u64)ret << blkbits;
		iomap->flags |= IOMAP_F_MERGED;
	}


	if (sbi->num_numa_nodes == 2) {
		byte_offset_in_dax = bno;
		if (byte_offset_in_dax >= sbi->initsize) {
			first_virt_end = (unsigned long) sbi->virt_addr +
				(unsigned long) sbi->pmem_size;
			second_virt_start = (unsigned long) sbi->virt_addr_2;
			diff_between_devs = second_virt_start - first_virt_end;
			byte_offset_in_dax -= diff_between_devs;
			iomap->offset = (sector_t)byte_offset_in_dax >> 9;
		}
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;

	duofs_dbg_verbose("%s: iomap->flags %d, iomap->offset %lld, iomap->blkno %lu, "
			 "iomap->length %llu\n", __func__, iomap->flags, iomap->offset,
			 (iomap->offset << blkbits), iomap->length);

	return 0;
}


int duofs_iomap_end(struct inode *inode, loff_t offset, loff_t length,
	ssize_t written, unsigned int flags, struct iomap *iomap)
{
	if (iomap->type == IOMAP_MAPPED &&
			written < length &&
			(flags & IOMAP_WRITE))
		truncate_pagecache(inode, inode->i_size);
	return 0;
}


static int duofs_iomap_begin_lock(struct inode *inode, loff_t offset,
	loff_t length, unsigned int flags, struct iomap *iomap)
{
	return duofs_iomap_begin(inode, offset, length, flags, iomap, true);
}

static struct iomap_ops duofs_iomap_ops_lock = {
	.iomap_begin	= duofs_iomap_begin_lock,
	.iomap_end	= duofs_iomap_end,
};

static inline int __duofs_get_block(struct inode *inode, pgoff_t pgoff,
				   unsigned long max_blocks, int create, u64 *result)
{
	int rc = 0;

	rc = duofs_find_and_alloc_blocks(inode, (sector_t)pgoff, max_blocks, result,
					create);
	return rc;
}

static vm_fault_t duofs_xip_huge_file_fault(struct vm_fault *vmf,
				    enum page_entry_size pe_size)
{
	vm_fault_t ret;
	int error = 0;
	pfn_t pfn;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	duofs_dbg_verbose("%s: inode %lu, pgoff %lu, pe_size %d\n",
			 __func__, inode->i_ino, vmf->pgoff, pe_size);

	if (vmf->flags & FAULT_FLAG_WRITE)
		file_update_time(vmf->vma->vm_file);

	ret = dax_iomap_fault(vmf, pe_size, &pfn, &error, &duofs_iomap_ops_lock);

	return ret;
}

static vm_fault_t duofs_dax_pfn_mkwrite(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	loff_t size;
	vm_fault_t ret;
	timing_t fault_time;

	inode_lock(inode);
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size)
		ret = VM_FAULT_SIGBUS;
	else
		ret = duofs_xip_huge_file_fault(vmf, PE_SIZE_PTE);
	inode_unlock(inode);

	return ret;
}

int duofs_get_xip_mem(struct address_space *mapping, pgoff_t pgoff,
		     unsigned long max_blocks, int create,
		      void **kmem, unsigned long *pfn)
{
	int rc;
	u64 block = 0;
	struct inode *inode = mapping->host;

	rc = __duofs_get_block(inode, pgoff, max_blocks, create, &block);
	if (rc <= 0) {
		duofs_dbg1("[%s:%d] rc(%d), sb->physaddr(0x%llx), block(0x%llx),"
			" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__,
			__LINE__, rc, DUOFS_SB(inode->i_sb)->phys_addr,
			block, pgoff, create, *pfn);
		return rc;
	}

	*kmem = duofs_get_block(inode->i_sb, block);
	*pfn = duofs_get_pfn(inode->i_sb, block);

	duofs_dbg_mmapvv("[%s:%d] sb->physaddr(0x%llx), block(0x%llx),"
		" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__, __LINE__,
		DUOFS_SB(inode->i_sb)->phys_addr, block, pgoff, create, *pfn);
	return rc;
}

static vm_fault_t duofs_dax_fault(struct vm_fault *vmf)
{
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	duofs_dbg_verbose("%s: inode %lu, pgoff %lu, flags 0x%x\n",
		  __func__, inode->i_ino, vmf->pgoff, vmf->flags);

	return duofs_xip_huge_file_fault(vmf, PE_SIZE_PTE);
}

static vm_fault_t duofs_xip_file_fault(struct vm_fault *vmf)
{
	int ret;
	timing_t fault_time;

	/*
	duofs_dbg("%s: got a 4K fault\n", __func__);
	return duofs_xip_huge_file_fault(vmf, PE_SIZE_PTE);
	*/
	DUOFS_START_TIMING(mmap_fault_t, fault_time);
	rcu_read_lock();
	ret = __duofs_xip_file_fault(vmf->vma, vmf);
	rcu_read_unlock();
	DUOFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static inline int duofs_rbtree_compare_vma(struct vma_item *curr,
	struct vm_area_struct *vma)
{
	if (vma < curr->vma)
		return -1;
	if (vma > curr->vma)
		return 1;

	return 0;
}

int duofs_insert_write_vma(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct duofs_inode_info *si = DUOFS_I(inode);
	struct duofs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	unsigned long flags = VM_SHARED | VM_WRITE;
	struct vma_item *item, *curr;
	struct rb_node **temp, *parent;
	int compVal;
	int insert = 0;
	int ret;
	timing_t insert_vma_time;
	struct duofs_inode *pi;
	struct process_numa *proc_numa;
	int cpu = duofs_get_cpuid(sb);


	if ((vma->vm_flags & flags) != flags)
		return 0;

	item = duofs_alloc_vma_item(sb);
	if (!item) {
		return -ENOMEM;
	}

	item->vma = vma;

	duofs_dbg_verbose("Inode %lu insert vma %p, start 0x%lx, end 0x%lx, pgoff %lu\n",
			 inode->i_ino, vma, vma->vm_start, vma->vm_end,
			 vma->vm_pgoff);

	pi = duofs_get_inode(sb, inode->i_ino);

	if (sbi->num_numa_nodes > 1 && pi->numa_node != sbi->cpu_numa_node[cpu]) {
		proc_numa = &(sbi->process_numa[current->tgid % sbi->num_parallel_procs]);
		if (proc_numa->tgid == current->tgid)
			proc_numa->numa_node = pi->numa_node;
		else {
			proc_numa->tgid = current->tgid;
			proc_numa->numa_node = pi->numa_node;
		}

		sched_setaffinity(current->pid, &(sbi->numa_cpus[pi->numa_node].cpumask));
	}

	inode_lock(inode);

	temp = &(sih->vma_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct vma_item, node);
		compVal = duofs_rbtree_compare_vma(curr, vma);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			duofs_dbg("%s: vma %p already exists\n",
				__func__, vma);
			kfree(item);
			goto out;
		}
	}

	rb_link_node(&item->node, parent, temp);
	rb_insert_color(&item->node, &sih->vma_tree);

	sih->num_vmas++;
	if (sih->num_vmas == 1)
		insert = 1;

out:
	inode_unlock(inode);

	return ret;
}

static int duofs_remove_write_vma(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct duofs_inode_info *si = DUOFS_I(inode);
	struct duofs_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	struct vma_item *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int found = 0;
	int remove = 0;
	timing_t remove_vma_time;

	inode_lock(inode);

	temp = sih->vma_tree.rb_node;
	while (temp) {
		curr = container_of(temp, struct vma_item, node);
		compVal = duofs_rbtree_compare_vma(curr, vma);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			rb_erase(&curr->node, &sih->vma_tree);
			found = 1;
			break;
		}
	}

	if (found) {
		sih->num_vmas--;
		if (sih->num_vmas == 0)
			remove = 1;
	}

	inode_unlock(inode);

	if (found) {
		duofs_dbg_verbose("Inode %lu remove vma %p, start 0x%lx, end 0x%lx, pgoff %lu\n",
				 inode->i_ino,	curr->vma, curr->vma->vm_start,
				 curr->vma->vm_end, curr->vma->vm_pgoff);
		duofs_free_vma_item(sb, curr);
	}

	return 0;
}

static void duofs_vma_open(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	duofs_dbg_mmap4k("[%s:%d] inode %lu, MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm pgoff %lu, %lu blocks, vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
			__func__, __LINE__,
			inode->i_ino, vma->vm_start, vma->vm_end,
			vma->vm_pgoff,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
			vma->vm_flags,
			pgprot_val(vma->vm_page_prot));

	duofs_insert_write_vma(vma);
}

static void duofs_vma_close(struct vm_area_struct *vma)
{
	duofs_dbg_verbose("[%s:%d] MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
		  __func__, __LINE__, vma->vm_start, vma->vm_end,
		  vma->vm_flags, pgprot_val(vma->vm_page_prot));

	vma->original_write = 0;
	duofs_remove_write_vma(vma);
}

static const struct vm_operations_struct duofs_xip_vm_ops = {
	.fault	= duofs_dax_fault,
	.huge_fault = duofs_xip_huge_file_fault,
	.page_mkwrite = duofs_dax_fault,
	.pfn_mkwrite = duofs_dax_pfn_mkwrite,
	.open = duofs_vma_open,
	.close = duofs_vma_close,
};

int duofs_xip_file_mmap(struct file *file, struct vm_area_struct *vma)
{
//	BUG_ON(!file->f_mapping->a_ops->get_xip_mem);

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

	vma->vm_ops = &duofs_xip_vm_ops;

	duofs_insert_write_vma(vma);

	duofs_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}