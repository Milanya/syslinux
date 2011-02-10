/* ----------------------------------------------------------------------- *
 *
 * 	 Copyright 2011 Paulo Alcantara <pcacjr@gmail.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * ntfs.c - Initial sanity check for NTFS-based installers
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

/*
 * Check to see that what we got was indeed an NTFS boot sector/superblock;
 * Return NULL if OK and otherwise an error message;
 */
const char *syslinux_check_ntfs_bootsect(const void *bs, long long clusters)
{
	const struct ntfs_boot_sector *sectbuf = bs;
//	int clustersize = get_8(&sectbuf->bsSecPerClust);

	/* By default, the maximum NTFS volume size is 2^32 clusters minus
	 * 1 cluster;
	 *
	 */
	/*if (clusters > ((clustersize * (1 << 32)) - clustersize))
		return "more than 2^32 clusters minus 1 cluster but claims NTFS";
	*/

	if (!clusters || !sectbuf)
		return NULL;

	return NULL;
}
