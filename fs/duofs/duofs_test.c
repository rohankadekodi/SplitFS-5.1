/*
 * BRIEF DESCRIPTION
 *
 * duofs test module.
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
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include "duofs.h"
#include "inode.h"

int __init test_duofs_write(void)
{
	struct duofs_super_block *psb;

	psb = get_duofs_super();
	if (!psb) {
		printk(KERN_ERR
		       "%s: duofs super block not found (not mounted?)\n",
		       __func__);
		return 1;
	}

	/*
	 * Attempt an unprotected clear of checksum information in the
	 * superblock, this should cause a kernel page protection fault.
	 */
	printk("%s: writing to kernel VA %p\n", __func__, psb);
	psb->s_sum = 0;

	return 0;
}

void test_duofs_write_cleanup(void)
{
}

/* Module information */
MODULE_LICENSE("GPL");
module_init(test_duofs_write);
module_exit(test_duofs_write_cleanup);
