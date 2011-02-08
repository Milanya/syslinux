/*
 *   Copyright (C) 2011 Paulo Alcantara <pcacjr@gmail.com>
 *
 *   Permission is hereby granted, free of charge, to any person
 *   obtaining a copy of this software and associated documentation
 *   files (the "Software"), to deal in the Software without
 *   restriction, including without limitation the rights to use,
 *   copy, modify, merge, publish, distribute, sublicense, and/or
 *   sell copies of the Software, and to permit persons to whom
 *   the Software is furnished to do so, subject to the following
 *   conditions:
 *
 *   The above copyright notice and this permission notice shall
 *   be included in all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *   OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <dprintf.h>
#include <stdio.h>
#include <string.h>
#include <sys/dirent.h>
#include <cache.h>
#include <core.h>
#include <disk.h>
#include <fs.h>
#include <ilog2.h>
#include <klibc/compiler.h>

#include "ntfs.h"

static int ntfs_fs_init(struct fs_info *fs)
{
    struct ntfs_boot_sector ntfs;
    struct ntfs_region *ntfs_reg;
    struct disk *disk = fs->fs_dev->disk;

    /* We need to retrieve the NTFS boot sector from CHS(0, 0, 1) or LBA 0 */
    if (!disk->rdwr_sectors(disk, &ntfs, 0, 1, 0))
		goto err;

    fs->sector_shift = fs->block_shift = disk->sector_shift;
    fs->sector_size = 1 << fs->sector_shift;
    fs->block_size = 1 << fs->block_shift;

    /* Need to allocate our in-memory NTFS region */
    ntfs_reg = malloc(sizeof(*ntfs_reg));
    if (!ntfs_reg)
		malloc_error("ntfs_region structure");
    	
	fs->fs_info = ntfs_reg;
    
	ntfs_reg->clust_shift = ilog2(ntfs.sectors_per_cluster);
    ntfs_reg->clust_mask = ntfs.sectors_per_cluster - 1;
    ntfs_reg->clust_size = ntfs.sectors_per_cluster << fs->sector_shift;

    printf("NTFS region:\n"
	   "clust_shift: 0x%8x\nclust_mask: 0x%8x\n"
	   "clust_size: 0x%8x\n",
	   ntfs_reg->clust_shift, ntfs_reg->clust_mask, ntfs_reg->clust_size);

    printf("execution stops here! :-)\n");
    for (;;) ;

    return 0;			/* let's assume that all went ok... */

err:
    printf("ERROR: rdwr_sectors()\n");
    for (;;) ;
}

const struct fs_ops ntfs_fs_ops = {
    .fs_name = "ntfs",
    .fs_flags = FS_USEMEM | FS_THISIND,
    .fs_init = ntfs_fs_init,
    .searchdir = NULL,
    .getfssec = NULL,
    .close_file = NULL,
    .mangle_name = NULL,
    .load_config = NULL,
    .readdir = NULL,
    .iget_root = NULL,
    .next_extent = NULL,
};
