#include "duofs.h"
#include "inode.h"

const char *Timingstring[TIMING_NUM] = 
{
	"create",
	"unlink",
	"readdir",
	"xip_read",
	"xip_write",
	"xip_write_fast",
	"internal_write",
	"memcpy_read",
	"memcpy_write",
	"alloc_blocks",
	"new_trans",
	"add_logentry",
	"commit_trans",
	"mmap_fault",
	"fsync",
	"free_tree",
	"evict_inode",
	"recovery",
};

unsigned long long Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];

atomic64_t fsync_pages = ATOMIC_INIT(0);

void duofs_print_IO_stats(void)
{
	printk("=========== duofs I/O stats ===========\n");
	printk("Fsync %ld pages\n", atomic64_read(&fsync_pages));
}

void duofs_print_available_hugepages(struct super_block *sb)
{
	struct duofs_sb_info *sbi = DUOFS_SB(sb);
	int i;
	unsigned long num_hugepages = 0;
	struct free_list *free_list;


	printk("======== duofs Available Free Hugepages =======\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = duofs_get_free_list(sb, i);
		num_hugepages += free_list->num_blocknode_huge_aligned;
		printk("free list idx %d, free hugepages %lu, free unaligned pages %lu\n",
		       free_list->index, free_list->num_blocknode_huge_aligned,
		       free_list->num_blocknode_unaligned);
	}
	printk("Total free hugepages %lu\n",
	       num_hugepages);
}

void duofs_print_timing_stats(void)
{
	int i;

	printk("======== duofs kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		if (measure_timing || Timingstats[i]) {
			printk("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			printk("%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	duofs_print_IO_stats();
}

void duofs_clear_stats(void)
{
	int i;

	printk("======== Clear duofs kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
	}
}
