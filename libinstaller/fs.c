/* ----------------------------------------------------------------------- *
 *
 *   Copyright 1998-2011 H. Peter Anvin - All Rights Reserved
 *   Copyright 2009-2011 Intel Corporation; author H. Peter Anvin
 *   Copyright 2011 Paulo Alcantara <pcacjr@gmail.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * fs.c - Generic sanity check for FAT/NTFS-based installers
 */

#define _XOPEN_SOURCE 500	/* Required on glibc 2.x */
#define _BSD_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#include "syslinux.h"
#include "syslxint.h"
#include "syslxcom.h"

void syslinux_make_bootsect(void *bs, int fs_type)
{
    if (fs_type == VFAT) {
	struct fat_boot_sector *bootsect = bs;
	const struct fat_boot_sector *sbs;
	//(const struct fat_boot_sector *)boot_sector; ????????

	memcpy(&bootsect->FAT_bsHead, &sbs->FAT_bsHead, FAT_bsHeadLen);
	memcpy(&bootsect->FAT_bsCode, &sbs->FAT_bsCode, FAT_bsCodeLen);
    } else if (fs_type == NTFS) {
	struct ntfs_boot_sector *bootsect = bs;
	const struct ntfs_boot_sector *sbs;
	//(const struct ntfs_boot_sector *)boot_sector; ???????

	memcpy(&bootsect->NTFS_bsHead, &sbs->NTFS_bsHead, NTFS_bsHeadLen);
	memcpy(&bootsect->NTFS_bsCode, &sbs->NTFS_bsCode, NTFS_bsCodeLen);
    }
}

const char *syslinux_check_bootsect(const void *bs, int *fs_type)
{
    int sectorsize;
    long long sectors, fatsectors, dsectors;
    long long clusters;
    int rootdirents, clustersize;
    const struct boot_sector *sectbuf = bs;
    unsigned char media_sig;
    char *retval = NULL;

    media_sig = get_8(&sectbuf->bsMedia);
    /* Must be 0xF0 or 0xF8..0xFF for FAT/NTFS volumes */
    if (media_sig != 0xF0 && media_sig < 0xF8)
	return "invalid media signature (not an FAT/NTFS filesystem?)";

    sectorsize = get_16(&sectbuf->bsBytesPerSec);
    if (sectorsize == SECTOR_SIZE) ;	/* ok */
    else if (sectorsize >= 512 && sectorsize <= 4096 &&
	     (sectorsize & (sectorsize - 1)) == 0)
	return "unsupported sectors size";
    else
	return "impossible sector size";

    clustersize = get_8(&sectbuf->bsSecPerClust);
    if (clustersize == 0 || (clustersize & (clustersize - 1)))
	return "impossible cluster size";

    sectors = get_16(&sectbuf->bsSectors);
    sectors = sectors ? sectors : get_32(&sectbuf->bsHugeSectors);

    dsectors = sectors - get_16(&sectbuf->bsResSectors);

    fatsectors = get_16(&sectbuf->bsFATsecs);
    fatsectors = fatsectors ? fatsectors : get_32(&sectbuf->bs32.FATSz32);
    fatsectors *= get_8(&sectbuf->bsFATs);
    dsectors -= fatsectors;

    rootdirents = get_16(&sectbuf->bsRootDirEnts);
    dsectors -= (rootdirents + sectorsize / 32 - 1) / sectorsize;

    if (dsectors < 0)
	return "negative number of data sectors";

    clusters = dsectors / clustersize;
    /* Note: fatsectors and rootdirents must be 0 on NTFS volumes, otherwise
     * NTFS fails to mount
     */
    if (!fatsectors && !rootdirents) {
	retval = (char *)syslinux_check_ntfs_bootsect(bs, clusters);
	if (!retval) {
	    if (fs_type)
		*fs_type = NTFS;
	}
    } else if (!fatsectors) {
	return "zero FAT sectors";
    } else if ((!fatsectors && rootdirents) || (fatsectors && !rootdirents)) {
	return "FAT/NTFS boot sector somehow is messed up!";
    } else {
	retval = (char *)syslinux_check_fat_bootsect(bs, clusters);
	if (!retval) {
	    if (fs_type)
		*fs_type = VFAT;
	}
    }

    return retval;
}
