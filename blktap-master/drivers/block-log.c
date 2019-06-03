/*
 * Copyright (c) 2016, Citrix Systems, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the names of its 
 *     contributors may be used to endorse or promote products derived from 
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Driver to sit on top of another disk and log writes, in order
 * to track changed blocks
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "tapdisk-utils.h"
#include "timeout-math.h"
#include "log.h"
#include "block-log.h"

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)

#define BITMAP_ENTRY(_nr, _bmap) ((unsigned long*)(_bmap + sizeof(struct cbt_log_metadata)))[((_nr)/BITS_PER_LONG)]
#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

static inline int test_bit(int nr, void* bmap)
{
	return (BITMAP_ENTRY(nr, bmap) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void set_bit(int nr, void* bmap)
{
	BITMAP_ENTRY(nr, bmap) |= (1UL << BITMAP_SHIFT(nr));
}

static inline uint64_t
get_bit_for_sec(td_sector_t sector)
{
	uint64_t block = (sector * SECTOR_SIZE) / CBT_BLOCK_SIZE;
	return block;
}

static int bitmap_init(struct tdlog_data *data, char *name)
{
	uint64_t bmsize;
	int fd;
	int result = 0;

	/* Open on disk log file and map it into memory */
	fd = open(name, O_RDWR);
	if (fd == -1) {
		EPRINTF("failed to open bitmap log file");
		result = -1;
	}

	if (result == 0) {
		//data->size is in number of sectors, convert it to bytes
		bmsize = bitmap_size(data->size * SECTOR_SIZE) + sizeof(struct cbt_log_metadata);
		DPRINTF("CBT: allocating %"PRIu64" bytes (bitmap %"PRIu64" + header %lu) for dirty bitmap",
								bmsize, bitmap_size(data->size * SECTOR_SIZE),
											sizeof(struct cbt_log_metadata));

		data->bitmap = mmap(NULL, bmsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (!data->bitmap) {
			EPRINTF("could not allocate dirty bitmap of size %"PRIu64, bmsize);
			result = -1;
		}

		close (fd);
	}

	return result;
}

static int bitmap_free(struct tdlog_data *data)
{
	uint64_t bmsize;
	int rc;
	bmsize = bitmap_size(data->size * SECTOR_SIZE) + sizeof(struct cbt_log_metadata);
	if (data->bitmap) {
		rc = munmap(data->bitmap, bmsize);
		if (rc != 0) {
			EPRINTF("Failed to unmap the bitmap block");
		}
	}

	return 0;
}

static int bitmap_set(struct tdlog_data* data, uint64_t block, int count)
{
	int i;

	for (i = 0; i < count; i++)
		set_bit(block + i, data->bitmap);

	return 0;
}


/* -- interface -- */

static int tdlog_close(td_driver_t* driver)
{
	struct tdlog_data* data = (struct tdlog_data*)driver->data;
	bitmap_free(data);

	return 0;
}

static int tdlog_open(td_driver_t* driver, const char *name,
		      struct td_vbd_encryption *encryption, td_flag_t flags)
{
	struct tdlog_data* data = (struct tdlog_data*)driver->data;
	int rc;

	memset(data, 0, sizeof(*data));
	data->size = driver->info.size;

	if ((rc = bitmap_init(data, driver->name))) {
		tdlog_close(driver);
		return rc;
	}

	return 0;
}

static void tdlog_queue_read(td_driver_t* driver, td_request_t treq)
{
	td_forward_request(treq);
}

static void tdlog_queue_write(td_driver_t* driver, td_request_t treq)
{
	struct tdlog_data* data = (struct tdlog_data*)driver->data;
	uint64_t start_bit, last_bit;

	start_bit = get_bit_for_sec(treq.sec);
	last_bit = get_bit_for_sec(treq.sec + treq.secs - 1);

	bitmap_set(data, start_bit, (last_bit - start_bit) + 1);
	td_forward_request(treq);
}

static int tdlog_get_parent_id(td_driver_t* driver, td_disk_id_t* id)
{
	return -EINVAL;
}

static int tdlog_validate_parent(td_driver_t *driver,
				 td_driver_t *parent, td_flag_t flags)
{
	return 0;
}

struct tap_disk tapdisk_log = {
	.disk_type          = "tapdisk_log",
	.private_data_size  = sizeof(struct tdlog_data),
	.flags              = 0,
	.td_open            = tdlog_open,
	.td_close           = tdlog_close,
	.td_queue_read      = tdlog_queue_read,
	.td_queue_write     = tdlog_queue_write,
	.td_get_parent_id   = tdlog_get_parent_id,
	.td_validate_parent = tdlog_validate_parent,
};
