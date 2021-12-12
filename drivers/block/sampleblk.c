/*
 *   blk/sampleblk/sample_blk.c
 *
 *   Copyright (C) Oliver Yang 2016
 *   Author(s): Yong Yang (yangoliver@gmail.com)
 *
 *   Sample Block Driver
 *
 *   Primitive example to show how to create a Linux block driver
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>

static int sampleblk_major;
#define SAMPLEBLK_MINOR 1
static int sampleblk_sect_size = 512;
static int sampleblk_nsects = 10 * 1024;

struct sampleblk_dev {
	int minor;
	spinlock_t lock;
	struct blk_mq_tag_set tag_set;
	struct request_queue *queue;
	struct gendisk *disk;
	ssize_t size;
	void *data;
};

struct sampleblk_dev *sampleblk_dev = NULL;

/*
 * Do an I/O operation for each segment
 */
static int sampleblk_handle_io(struct sampleblk_dev *sampleblk_dev,
		uint64_t pos, ssize_t size, void *buffer, int write)
{
	if (write)
		memcpy(sampleblk_dev->data + pos, buffer, size);
	else
		memcpy(buffer, sampleblk_dev->data + pos, size);

	return 0;
}

static blk_status_t sampleblk_request(struct blk_mq_hw_ctx *hctx,
				     const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
#if 0
	int ret = 0;
	uint64_t pos = 0;
	ssize_t size = 0;
	struct bio_vec bvec;
	struct req_iterator iter;
	void *kaddr = NULL;
#endif

	blk_mq_start_request(rq);

	if (blk_rq_is_passthrough(rq)) {
		printk (KERN_NOTICE "Skip non-fs request\n");
		blk_mq_end_request(rq, BLK_STS_IOERR);
//		goto out;
	}

	blk_mq_end_request(rq, BLK_STS_OK);
#if 0
	while ((rq = blk_fetch_request(q)) != NULL) {
		spin_unlock_irq(q->queue_lock);

		if (rq->cmd_type != REQ_TYPE_FS) {
			ret = -EIO;
			goto skip;
		}

		BUG_ON(sampleblk_dev != rq->rq_disk->private_data);

		pos = blk_rq_pos(rq) * sampleblk_sect_size;
		size = blk_rq_bytes(rq);
		if ((pos + size > sampleblk_dev->size)) {
			pr_crit("sampleblk: Beyond-end write (%llu %zx)\n",
				pos, size);
			ret = -EIO;
			goto skip;
		}

		rq_for_each_segment(bvec, rq, iter) {
			kaddr = kmap(bvec.bv_page);

			ret = sampleblk_handle_io(sampleblk_dev, pos,
				bvec.bv_len, kaddr + bvec.bv_offset,
				rq_data_dir(rq));
			if (ret < 0)
				goto skip;

			pos += bvec.bv_len;
			kunmap(bvec.bv_page);
		}
skip:

		blk_mq_end_request(rq, BLK_STS_OK);

		spin_lock_irq(q->queue_lock);
	}
#endif
	return 0;
}

static int sampleblk_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned command, unsigned long argument)
{
	return 0;
}

static int sampleblk_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void sampleblk_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations sampleblk_fops = {
	.owner = THIS_MODULE,
	.open = sampleblk_open,
	.release = sampleblk_release,
	.ioctl = sampleblk_ioctl,
};

static struct blk_mq_ops sampleblk_queue_ops = {
	.queue_rq = sampleblk_request,
};

static int sampleblk_alloc(int minor)
{
	struct gendisk *disk;
	int ret = 0;

	sampleblk_dev = kzalloc(sizeof(struct sampleblk_dev), GFP_KERNEL);
	if (!sampleblk_dev) {
		ret = -ENOMEM;
		goto fail;
	}

	sampleblk_dev->size = sampleblk_sect_size * sampleblk_nsects;
	sampleblk_dev->data = vmalloc(sampleblk_dev->size);
	if (!sampleblk_dev->data) {
		ret = -ENOMEM;
		goto fail_dev;
	}
	sampleblk_dev->minor = minor;

	spin_lock_init(&sampleblk_dev->lock);

	/* Initialize tag set. */
	sampleblk_dev->tag_set.ops = &sampleblk_queue_ops;
	sampleblk_dev->tag_set.nr_hw_queues = 1;
	sampleblk_dev->tag_set.queue_depth = 128;
	sampleblk_dev->tag_set.numa_node = NUMA_NO_NODE;
	sampleblk_dev->tag_set.cmd_size = 0;
	sampleblk_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ret = blk_mq_alloc_tag_set(&sampleblk_dev->tag_set);
	if (ret) {
		goto fail_data;
	}

	/* Allocate queue. */
	sampleblk_dev->queue = blk_mq_init_queue(&sampleblk_dev->tag_set);
	if (IS_ERR(sampleblk_dev->queue)) {
		ret = -ENOMEM;
		goto fail_tag;
	}

	/* To inform the kernel about the device sector size. */
	blk_queue_logical_block_size(sampleblk_dev->queue, SECTOR_SIZE);

	/* Assign private data to queue structure. */
	sampleblk_dev->queue->queuedata = sampleblk_dev;

	/* Remove IO stack limits to avoid bio split */
	blk_set_stacking_limits(&sampleblk_dev->queue->limits);

	disk = alloc_disk(minor);
	if (!disk) {
		ret = -ENOMEM;
		goto fail_queue;
	}
	sampleblk_dev->disk = disk;

	disk->major = sampleblk_major;
	disk->first_minor = minor;
	disk->fops = &sampleblk_fops;
	disk->private_data = sampleblk_dev;
	disk->queue = sampleblk_dev->queue;
	sprintf(disk->disk_name, "sampleblk%d", minor);
	set_capacity(disk, sampleblk_nsects);
	add_disk(disk);

	return ret;

fail_queue:
	blk_cleanup_queue(sampleblk_dev->queue);
fail_tag:
	blk_mq_free_tag_set(&sampleblk_dev->tag_set);
fail_data:
	vfree(sampleblk_dev->data);
fail_dev:
	kfree(sampleblk_dev);
fail:
	return ret;
}

static void sampleblk_free(struct sampleblk_dev *sampleblk_dev)
{
	del_gendisk(sampleblk_dev->disk);
	blk_cleanup_queue(sampleblk_dev->queue);
	blk_mq_free_tag_set(&sampleblk_dev->tag_set);
	put_disk(sampleblk_dev->disk);
	vfree(sampleblk_dev->data);
	kfree(sampleblk_dev);
}

static int __init sampleblk_init(void)
{
	int ret = 0;

	sampleblk_major = register_blkdev(0, "sampleblk");
	if (sampleblk_major < 0)
		return sampleblk_major;

	ret = sampleblk_alloc(SAMPLEBLK_MINOR);
	if (ret < 0)
		pr_info("sampleblk: disk allocation failed with %d\n", ret);

	pr_info("sampleblk: module loaded\n");
	return ret;
}

static void __exit sampleblk_exit(void)
{
	sampleblk_free(sampleblk_dev);
	unregister_blkdev(sampleblk_major, "sampleblk");

	pr_info("sampleblk: module unloaded\n");
}

module_init(sampleblk_init);
module_exit(sampleblk_exit);
MODULE_LICENSE("GPL");
