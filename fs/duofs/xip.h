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

int duofs_get_xip_mem(struct address_space *, pgoff_t, unsigned long, int, void **,
		      unsigned long *);
ssize_t duofs_xip_file_read(struct file *filp, char __user *buf, size_t len,
			    loff_t *ppos);
ssize_t duofs_xip_cow_file_write(struct file *filp, const char __user *buf,
				size_t len, loff_t *ppos);
ssize_t duofs_xip_file_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos);
int duofs_xip_file_mmap(struct file *file, struct vm_area_struct *vma);

static inline int duofs_use_xip(struct super_block *sb)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);

	return sbi->s_mount_opt & DUOFS_MOUNT_XIP;
}

#define mapping_is_xip(map) (map->a_ops->get_xip_mem)