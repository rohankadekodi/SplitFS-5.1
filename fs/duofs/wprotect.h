/*
 * BRIEF DESCRIPTION
 *
 * Memory protection definitions for the duofs filesystem.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2010-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __WPROTECT_H
#define __WPROTECT_H

#include <linux/fs.h>
#include "duofs_def.h"

/* duofs_memunlock_super() before calling! */
static inline void duofs_sync_super(struct duofs_super_block *ps)
{
	u16 crc = 0;

	ps->s_wtime = cpu_to_le32(get_seconds());
	ps->s_sum = 0;
	crc = crc16(~0, (__u8 *)ps + sizeof(__le16),
			DUOFS_SB_STATIC_SIZE(ps) - sizeof(__le16));
	ps->s_sum = cpu_to_le16(crc);
	/* Keep sync redundant super block */
	memcpy((void *)ps + DUOFS_SB_SIZE, (void *)ps,
		sizeof(struct duofs_super_block));
}

#if 0
/* duofs_memunlock_inode() before calling! */
static inline void duofs_sync_inode(struct duofs_inode *pi)
{
	u16 crc = 0;

	pi->i_sum = 0;
	crc = crc16(~0, (__u8 *)pi + sizeof(__le16), DUOFS_INODE_SIZE -
		    sizeof(__le16));
	pi->i_sum = cpu_to_le16(crc);
}
#endif

extern int duofs_writeable(void *vaddr, unsigned long size, int rw);
extern int duofs_xip_mem_protect(struct super_block *sb,
				 void *vaddr, unsigned long size, int rw);

static inline int duofs_is_protected(struct super_block *sb)
{
	struct duofs_sb_info *sbi = (struct duofs_sb_info *)sb->s_fs_info;

	return sbi->s_mount_opt & DUOFS_MOUNT_PROTECT;
}

static inline int duofs_is_wprotected(struct super_block *sb)
{
	return duofs_is_protected(sb);
}

static inline void
__duofs_memunlock_range(void *p, unsigned long len)
{
	/*
	 * NOTE: Ideally we should lock all the kernel to be memory safe
	 * and avoid to write in the protected memory,
	 * obviously it's not possible, so we only serialize
	 * the operations at fs level. We can't disable the interrupts
	 * because we could have a deadlock in this path.
	 */
	duofs_writeable(p, len, 1);
}

static inline void
__duofs_memlock_range(void *p, unsigned long len)
{
	duofs_writeable(p, len, 0);
}

static inline void duofs_memunlock_range(struct super_block *sb, void *p,
					 unsigned long len)
{
	if (duofs_is_protected(sb))
		__duofs_memunlock_range(p, len);
}

static inline void duofs_memlock_range(struct super_block *sb, void *p,
				       unsigned long len)
{
	if (duofs_is_protected(sb))
		__duofs_memlock_range(p, len);
}

static inline void duofs_memunlock_super(struct super_block *sb,
					 struct duofs_super_block *ps)
{
	if (duofs_is_protected(sb))
		__duofs_memunlock_range(ps, DUOFS_SB_SIZE);
}

static inline void duofs_memlock_super(struct super_block *sb,
				       struct duofs_super_block *ps)
{
	duofs_sync_super(ps);
	if (duofs_is_protected(sb))
		__duofs_memlock_range(ps, DUOFS_SB_SIZE);
}

static inline void duofs_memunlock_inode(struct super_block *sb,
					 struct duofs_inode *pi)
{
	if (duofs_is_protected(sb))
		__duofs_memunlock_range(pi, DUOFS_SB_SIZE);
}

static inline void duofs_memlock_inode(struct super_block *sb,
				       struct duofs_inode *pi)
{
	/* duofs_sync_inode(pi); */
	if (duofs_is_protected(sb))
		__duofs_memlock_range(pi, DUOFS_SB_SIZE);
}

static inline void duofs_memunlock_block(struct super_block *sb, void *bp)
{
	if (duofs_is_protected(sb))
		__duofs_memunlock_range(bp, sb->s_blocksize);
}

static inline void duofs_memlock_block(struct super_block *sb, void *bp)
{
	if (duofs_is_protected(sb))
		__duofs_memlock_range(bp, sb->s_blocksize);
}

#endif
