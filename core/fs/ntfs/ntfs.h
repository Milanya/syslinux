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

#include <stdint.h>

#ifndef _NTFS_H_
#define _NTFS_H_

/* NTFS file flags */
/* These are used by flag field in struct ntfs_frec_seg_header */
#define NTFS_FREC_SEG_IN_USE		0x0001
#define NTFS_FILE_NAME_IDX_PRESENT	0x0002

/* NTFS attribute type codes */
#define NTFS_STD_INFO			0x10
#define NTFS_ATTR_LIST			0x20
#define NTFS_FILE_NAME			0x30
#define NTFS_VOL_VERSION		0x40	/* NT */
#define NTFS_OBJ_ID			0x40	/* 2K */
#define NTFS_SECURITY_DESC		0x50
#define NTFS_VOL_NAME			0x60
#define NTFS_VOL_INFO			0x70
#define NTFS_DATA			0x80
#define NTFS_INDEX_ROOT			0x90
#define NTFS_INDEX_ALLOCATION		0xA0
#define NTFS_BITMAP			0xB0
#define NTFS_SYMLINK			0xC0	/* NT */
#define NTFS_EA_INFO			0xD0	/* 2K */
#define NTFS_EA				0xE0
#define NTFS_PROPERTY_SET		0xF0	/* NT */
#define NTFS_LOGGED_UTILITY_STREAM	0x100	/* 2K */

/* NTFS file permissions (also called attributes in DOS terminology) */
#define NTFS_ATTR_READ_ONLY		0x0001
#define NTFS_ATTR_HIDDEN		0x0002
#define NTFS_ATTR_SYSTEM		0x0004
#define NTFS_ATTR_ARCHIVE		0x0020
#define NTFS_ATTR_DEVICE		0x0040
#define NTFS_ATTR_NORMAL		0x0080
#define NTFS_ATTR_TEMPORARY		0x0100
#define NTFS_ATTR_SPARSE_FILE		0x0200
#define NTFS_ATTR_REPARSE_POINT		0x0400
#define NTFS_ATTR_COMPRESSED		0x0800
#define NTFS_ATTR_OFFLINE		0x1000
#define NTFS_ATTR_NC_INDEXED		0x2000	/* Not Content Indexed */
#define NTFS_ATTR_ENCRYPTED		0x4000

/* Directory (copy from corresponding bit in MFT record) */
#define NTFS_ATTR_DIR 			0x10000000
/* Index View (copy from corresponding bit in MFT record) */
#define NTFS_ATTR_INDEX_VIEW		0x20000000
/* Used in ntfs_index_header structure */
#define NTFS_LARGE_INDEX 		0x01	/* Index Allocation needed */

/* $STANDARD_INFORMATION */
struct ntfs_std_info {
    /* standard attribute header */
    uint8_t ctime[8];		/* C Time - File Creation */
    uint8_t atime[8];		/* A Time - File Altered */
    uint8_t mtime[8];		/* M Time - MFT Changed */
    uint8_t rtime[8];		/* R Time - File Read */
    uint32_t dos_fperm;		/* DOS file permissions */
    uint32_t max_nr_versions;	/* Maximum Number of Versions */
    uint32_t ver_nr;		/* Version Number */
    uint32_t class_id;		/* Class ID */
    uint32_t owner_id;		/* Owner ID (2K) */
    uint32_t sec_id;		/* Security ID (2K) */
    uint8_t quota_chd[8];	/* Quota Charged (2K) */
    uint8_t usn;		/* Update Sequence Number (2K) */
} __attribute__ ((packed));

/* $ATTRIBUTE_LIST */
struct ntfs_attr_list {
    uint32_t type;
    uint16_t rec_len;		/* Record Length */ ;
    uint8_t name_len;
    uint8_t name_offset;
    uint8_t start_vcn[8];	/* Always seems to be zero, check */
    uint8_t bfile_ref[8];	/* Base File Reference of the attribute */
    uint16_t attr_id;
    uint16_t name;
} __attribute__ ((packed));

/* $FILENAME */
struct ntfs_file_name {
    uint8_t fref_parent_dir[8];	/* File reference to the parent directory */
    uint8_t ctime[8];		/* C Time - File Creation */
    uint8_t atime[8];		/* A Time - File Altered */
    uint8_t mtime[8];		/* M Time - MFT Changed */
    uint8_t rtime[8];		/* R Time - File Read */
    uint8_t allocated_size[8];	/* Allocated size of the file */
    uint8_t real_size[8];	/* Real size of the file */
    uint32_t flags;		/* Flags (e.g. directory, compressed, hidden) */
    uint32_t foo;		/* Used by EAs and Reparse */
    uint8_t fname_len;		/* Filename length in chars (L) */
    uint8_t fname_namespace;	/* Filename namespace */
} __attribute__ ((packed));

/* $INDEX_ROOT
 * This is the root node of the B+ tree that implements an index
 * (e.g. a directory). This file attribute is always resident
 */
struct ntfs_index_root {
    uint32_t attr_type;		/* Attribute Type */
    uint32_t col_rule;		/* Collation Rule */
    uint32_t entry_size;	/* Size of Index Allocation Entry (bytes) */
    uint8_t clust_per_irec;	/* Clusters per Index Record */
    uint8_t pad[3];		/* Padding (align to 8 bytes) */
} __attribute__ ((packed));

struct ntfs_index_header {
    uint32_t offset;		/* Offset to first Index Entry */
    uint32_t total_size;	/* Total size of the Index Entries */
    uint32_t asize;		/* Allocated size of the Index Entries */
    uint8_t flags;
    uint8_t pad[3];		/* Padding (align to 8 bytes) */
} __attribute__ ((packed));

/* The NTFS file system structures */
/* Note: the BPB is stored in a packed (unaligned) format */
struct ntfs_boot_sector {
    uint8_t jmp[3];		/* An x86-based CPU jump instruction */
    uint8_t oem_id[8];		/* The OEM Identification */
    uint16_t sector_size;
    /* Number of sectors per cluster (allocation unit). This value must be
     * power of 2 that is greater than 0. E.g. 1, 2, 4, 8 and so on.
     */
    uint8_t sectors_per_cluster;
    /* Always 0 because NTFS places the boot sector af the
     * beginning of the partition
     */
    uint16_t reserved_sectors;
    /* These 3 bytes are used to store FAT information and full of zeroes
     * on NTFS volumes
     */
    uint8_t zo_0[3];		/* Not used by NTFS */
    uint16_t zo_1;
    uint8_t media_desc;		/* Media Descriptor ID */
    uint16_t zo_2;		/* Must be set to 0 for NTFS volumes */
    uint8_t unused_0[8];	/* Not used or checked by NTFS */
    uint32_t zo_4;		/* Must be set to 0 for NTFS volumes */
    uint32_t unused_1;		/* Not used or checked by NTFS */
    uint32_t total_sectors_low;	/* The total number of on-disk sectors */
    uint32_t total_sectors_high;
    /* Logical cluster number for the File $MFT */
    /* Identifies the location of the $MFT by using its
     * logical cluster number
     */
    uint32_t mft_lclust_low;
    uint32_t mft_lclust_high;;
    /* Logical cluster number for the File $MFTMirr. */
    /* Identifies the location of the mirrored copy of the
     * $MFT by using its logical cluster number
     */
    uint32_t mft_mirr_lclust_low;
    uint32_t mft_mirr_lclust_high;
    uint8_t clusters_per_mft_record;
    uint8_t unused_2[3];	/* Not used or checked by NTFS */
    uint8_t clusters_per_ibuf;	/* Clusters Per Index Buffer */
    uint8_t unused_3[3];	/* Not used or checked by NTFS */
    uint8_t vol_serial_nr[8];	/* Volume Serial Number */
    uint32_t unused_4;		/* Not used or checked by NTFS */
    uint8_t pad[428];		/* padding to 512 bytes (sector boundary) */
} __attribute__ ((packed));

/* In-memory organization of an NTFS Volume */
struct ntfs_region {
    sector_t mft;		/* NTFS MFT region */
    sector_t data;		/* NTFS data region */
    int clust_shift;		/* Based on sectors */
    int clust_mask;		/* Sectors per cluster mask */
    int clust_size;
    uint32_t clusters;		/* Total number of clusters */

    /* maybe some more info here... */
} __attribute__ ((packed));

/* NTFS MFT segment reference
 * Represents an address in the master file table (MFT)
 * The address is tagged with a circularly reused sequence number that is
 * set at the time the MFT segment reference was valid
 */
struct ntfs_mft_seg_ref {
    uint32_t seg_nr_low;	/* Segment number low part */
    uint16_t seg_nr_high;	/* Segment number high part */
    uint16_t seq_nr;		/* Sequence number */
} __attribute__ ((packed));

/* NTFS multisector header */
struct ntfs_msec_header {
    uint8_t sig[4];		/* Signature */
    uint16_t us_arr_offset;	/* Update Sequence Array Offset */
    uint16_t us_arr_size;	/* Update Sequence Array Size */
} __attribute__ ((packed));

/* NTFS file record segment header
 * Note: Each file record segment starts with a file record segment header
 * This is the header for each file record segment in the MFT
 */
struct ntfs_frec_seg_header {
    struct ntfs_msec_header mheader;
    uint64_t reserved_0;
    uint16_t seq_nr;
    uint16_t reserved_1;
    uint16_t first_attr_offset;
    uint16_t flags;
    uint32_t reserved_2[2];
    struct ntfs_mft_seg_ref base_frec_seg;
    uint16_t reserved_3;
    uint32_t us_arr;	/* FIXME: type is actually UPDATE_SEQUENCE_ARRAY */
} __attribute__ ((packed));

/* NTFS attribute record header
 * Represents an attribute record
 */
struct ntfs_attr_rec_header {
    uint8_t type_code;
    uint32_t rec_len;		/* Record length */
    uint8_t form_code;
    uint8_t name_len;
    uint16_t name_offset;
    uint16_t flags;
    uint16_t instance;
    union {
	struct {
	    uint32_t val_len;
	    uint16_t val_offset;
	    uint8_t reserved[2];
	} __attribute__ ((packed)) resident;
	struct {
	    uint64_t low_vcn;
	    uint64_t high_vcn;
	    uint16_t mpair_offset;
	    uint8_t reserved[6];
	    int64_t allocated_len;
	    int64_t file_size;
	    int64_t valid_data_len;
	    int64_t total_allocated;
	} __attribute__ ((packed)) nonresident;
    } __attribute__ ((packed)) form;
} __attribute__ ((packed));

/* NTFS private inode information */
struct ntfs_pvt_inode {
    uint32_t start_cluster;	/* Starting cluster addr */
    sector_t start;		/* Starting sector */
    sector_t offset;		/* Current sector offset */
    sector_t here;		/* Sector corresponding to offset */
};

#endif /* _NTFS_H_ */
