/* ----------------------------------------------------------------------- *
 *
 *   Copyright 1998-2008 H. Peter Anvin - All Rights Reserved
 *   Copyright 2009-2010 Intel Corporation; author H. Peter Anvin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * fat.c - Initial sanity check for FAT-based installers
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

/*
 * Check to see that what we got was indeed an MS-DOS boot sector/superblock;
 * Return NULL if OK and otherwise an error message;
 */
const char *syslinux_check_fat_bootsect(const void *bs, long long clusters)
{
    const struct boot_sector *sectbuf = bs;

    if (clusters < 0xFFF5) {
	/* FAT12 or FAT16 */

	if (!get_16(&sectbuf->bsFATsecs))
	    return "zero FAT sectors (FAT12/16)";

	if (get_8(&sectbuf->bs16.BootSignature) == 0x29) {
	    if (!memcmp(&sectbuf->bs16.FileSysType, "FAT12   ", 8)) {
		if (clusters >= 0xFF5)
		    return "more than 4084 clusters but claims FAT12";
	    }
	} else if (!memcmp(&sectbuf->bs16.FileSysType, "FAT16   ", 8)) {
	    if (clusters < 0xFF5)
		return "less than 4084 clusters but claims FAT16";
	} else if (!memcmp(&sectbuf->bs16.FileSysType, "FAT32   ", 8)) {
	    return "less than 65525 clusters but claims FAT32";
	} else if (memcmp(&sectbuf->bs16.FileSysType, "FAT     ", 8)) {
	    static char fserr[] = "filesystem type \"????????\" not supported";
	    memcpy(fserr + 17, &sectbuf->bs16.FileSysType, 8);
	    return fserr;
	}
    } else if (clusters < 0x0FFFFFF5) {
	/*
	 * FAT32...
	 *
	 * Moving the FileSysType and BootSignature was a lovely stroke
	 * of M$ idiocy...
	 */
	if (get_8(&sectbuf->bs32.BootSignature) != 0x29 ||
	    memcmp(&sectbuf->bs32.FileSysType, "FAT32   ", 8)) {
	    return "missing FAT32 signature";
	} else {
	    return "impossibly large number of clusters";
	}
    }

    return NULL;
}
