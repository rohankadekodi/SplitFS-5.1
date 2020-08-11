/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
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
#include <linux/namei.h>
#include "duofs.h"
#include "inode.h"

int duofs_block_symlink(struct inode *inode, const char *symname, int len)
{
	struct super_block *sb = inode->i_sb;
	u64 block;
	char *blockp;
	int err;

	err = duofs_alloc_blocks_weak(NULL, inode, 0, 1,
				false, ANY_CPU, 0);
	if (err)
		return err;

	duofs_find_data_blocks(inode, 0, &block, 1);
	blockp = duofs_get_block(sb, block);

	duofs_memunlock_block(sb, blockp);
	memcpy(blockp, symname, len);
	blockp[len] = '\0';
	duofs_memlock_block(sb, blockp);
	duofs_flush_buffer(blockp, len+1, false);
	return 0;
}

/* FIXME: Temporary workaround */
static int duofs_readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

static int duofs_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	u64 block;
	char *blockp;

	duofs_find_data_blocks(inode, 0, &block, 1);
	blockp = duofs_get_block(sb, block);
	return duofs_readlink_copy(buffer, buflen, blockp);
}

static const char *duofs_get_link(struct dentry *dentry, struct inode *inode,
	struct delayed_call *done)
{
	struct super_block *sb = inode->i_sb;
	u64 block;
	char *blockp;

	duofs_find_data_blocks(inode, 0, &block, 1);
	blockp = duofs_get_block(sb, block);
	return blockp;
}

const struct inode_operations duofs_symlink_inode_operations = {
	.readlink	= duofs_readlink,
	.get_link	= duofs_get_link,
	.setattr	= duofs_notify_change,
};
