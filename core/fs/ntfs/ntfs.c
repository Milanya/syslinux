/* ----------------------------------------------------------------------- *
 *
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
 * ntfs.c - The NTFS file system functions
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

#include "codepage.h"
#include "ntfs.h"

#define for_each_mft_record(fs, data, block) \
    for ((data) = ntfs_get_right_block((fs), (block)); \
            (block) < NTFS_SB((fs))->mft_size && \
            (((const MFT_RECORD *)(data))->magic == NTFS_MAGIC_FILE && \
            ((const MFT_RECORD *)(data))->mft_record_no != FILE_reserved12 && \
            ((const MFT_RECORD *)(data))->mft_record_no != FILE_reserved13 && \
            ((const MFT_RECORD *)(data))->mft_record_no != FILE_reserved14 && \
            ((const MFT_RECORD *)(data))->mft_record_no != FILE_reserved15 && \
            ((const MFT_RECORD *)(data))->mft_record_no != FILE_reserved16); \
            (block) += ((const MFT_RECORD *)(data))->bytes_allocated >> \
                                                        BLOCK_SHIFT((fs)), \
            (data) = ntfs_get_right_block((fs), (block)))

/* NTFS sanity check */
static inline int ntfs_check_zeroed_fields(struct ntfs_bpb *ntfs)
{
    return !ntfs->res_sectors && (!ntfs->zeroed_0[0] && !ntfs->zeroed_0[1] &&
            !ntfs->zeroed_0[2]) && !ntfs->zeroed_1 && !ntfs->zeroed_2 &&
            !ntfs->zeroed_3;
}

static inline struct inode *ntfs_inode_alloc(struct fs_info *fs)
{
    struct inode *inode = alloc_inode(fs, 0, sizeof(struct ntfs_inode));
    if (!inode)
        malloc_error("inode structure");

    return inode;
}

static inline const void *ntfs_get_right_block(struct fs_info *fs,
                                                        block_t block)
{
    return get_cache(fs->fs_dev, NTFS_SB(fs)->mft + block);
}

/* 0: success; -1: error */
static int ntfs_next_extent(struct inode *inode, uint32_t lstart)
{
    (void)inode;
    (void)lstart;

    return 0;
}

static const MFT_RECORD *ntfs_mft_record_lookup(uint32_t file,
                                                struct fs_info *fs,
                                                sector_t *block)
{
    const uint8_t *data;

    for_each_mft_record(fs, data, *block) {
        const MFT_RECORD *mrec;

        mrec = (const MFT_RECORD *)data;
        if (mrec->mft_record_no == file)
            return mrec;
    }

    return NULL;
}

static const ATTR_RECORD *ntfs_attr_lookup(uint32_t type,
                                            const MFT_RECORD *mrec)
{
    const ATTR_RECORD *attr;

    /* sanity check */
    if (!mrec || type == NTFS_AT_END)
        return NULL;

    attr = (const ATTR_RECORD *)((uint8_t *)mrec + mrec->attrs_offset);
    /* walk through the file attribute records */
    for (;; attr = (const ATTR_RECORD *)((uint8_t *)attr + attr->len)) {
        if (attr->type == NTFS_AT_END)
            return NULL;

        if (attr->type == type)
            break;
    }

    return attr;
}

static inline void print_unicode_charset(const uint16_t *stream)
{
    uint8_t *c = (uint8_t *)stream;

    for ( ; c && *c; printf("%c", *c), c += sizeof(*stream));
    printf("\n");
}

static void ntfs_printf_vol_info(struct fs_info *fs)
{
    const MFT_RECORD *mrec;
    sector_t block;
    const ATTR_RECORD *attr;
    const VOLUME_NAME *vn;
    const VOLUME_INFORMATION *vi;

    mrec = ntfs_mft_record_lookup(FILE_Volume, fs, &block);
    if (!mrec) {
        printf("No MFT record found!\n");
        return;
    }

    attr = ntfs_attr_lookup(NTFS_AT_VOL_NAME, mrec);
    if (!attr) {
        printf("No attribute found!\n");
        return;
    }

    vn = (const VOLUME_NAME *)((uint8_t *)attr +
                            attr->data.resident.value_offset);

    printf("Volume Name: ");
    print_unicode_charset(vn->name);

    attr = ntfs_attr_lookup(NTFS_AT_VOL_INFO, mrec);
    if (!attr) {
        printf("No attribute found!\n");
        return;
    }

    vi = (const VOLUME_INFORMATION *)((uint8_t *)attr +
                                    attr->data.resident.value_offset);
    printf("Volume Version: %d.%d\n", vi->major_ver, vi->minor_ver);
}

enum {
    MAP_UNSPEC,
    MAP_START           = 1 << 0,
    MAP_END             = 1 << 1,
    MAP_ALLOCATED       = 1 << 2,
    MAP_UNALLOCATED     = 1 << 3,
    MAP_MASK            = 0x0000000F,
};

struct mapping_chunk {
    uint64_t cur_vcn;   /* Current Virtual Cluster Number */
    uint8_t vcn_len;    /* Virtual Cluster Number length in bytes */
    uint64_t next_vcn;  /* Next Virtual Cluster Number */
    uint8_t lcn_len;    /* Logical Cluster Number length in bytes */
    int64_t cur_lcn;    /* Logical Cluster Number offset */
    uint32_t flags;     /* Specific flags of this chunk */
};

/* Parse data run */
static int parse_data_run(const void *stream, uint32_t *offset,
                            uint8_t *attr_len, struct mapping_chunk *chunk)
{
    uint8_t *buf;   /* Pointer to the zero-terminated byte stream */
    uint8_t count;  /* The count byte */
    uint8_t v, l;   /* v is the number of changed low-order VCN bytes;
                     * l is the number of changed low-order LCN bytes
                     */
    uint8_t *byte;
    int byte_shift = 8;
    int mask;
    uint8_t val;
    int64_t res;

    (void)attr_len;

    chunk->flags &= ~MAP_MASK;

    buf = (uint8_t *)stream + *offset;
    if (buf > attr_len || !*buf) {
        chunk->flags |= MAP_END;    /* we're done */
        return 0;
    }

    if (!*offset)
        chunk->flags |= MAP_START;  /* initial chunk */

    chunk->cur_vcn = chunk->next_vcn;

    count = *buf;
    v = count & 0x0F;
    l = count >> 4;

    if (v > 8 || l > 8) /* more than 8 bytes ? */
        goto out;

    chunk->vcn_len = v;
    chunk->lcn_len = l;

    byte = (uint8_t *)buf + v;
    count = v;

    res = 0LL;
    while (count--) {
        val = *byte--;
        mask = val >> (byte_shift - 1);
        res = (res << byte_shift) | ((val + mask) ^ mask);
    }

    chunk->next_vcn += res;

    byte = (uint8_t *)buf + v + l;
    count = l;

    mask = 0xFFFFFFFF;
    res = 0LL;
    if (*byte & 0x80)
        res |= (int64_t)mask;   /* sign-extend it */

    while (count--)
        res = (res << byte_shift) | *byte--;

    chunk->cur_lcn += res;
    if (!chunk->cur_lcn) {  /* is LCN 0 ? */
        /* then VCNS from cur_vcn to next_vcn - 1 are unallocated */
        chunk->flags |= MAP_UNALLOCATED;
    } else {
        /* otherwise they're all allocated */
        chunk->flags |= MAP_ALLOCATED;
    }

    *offset += v + l + 1;

    return 0;

out:
    return -1;
}

static struct inode *ntfs_find_entry(const char *dname, struct inode *dir)
{
    struct fs_info *fs = dir->fs;
    const MFT_RECORD *mrec;
    sector_t block;
    const ATTR_RECORD *attr;
    const INDEX_ROOT *ir;
    uint32_t len;
    const INDEX_ENTRY *ie;
    const INDEX_ALLOCATION *ia;
    uint8_t *stream;
    uint32_t offset;
    uint8_t *attr_len;
    struct mapping_chunk chunk;
    int err;
    struct inode *inode;

    (void)ia;
    (void)dname;

    block = NTFS_PVT(dir)->start;
    mrec = ntfs_mft_record_lookup(NTFS_PVT(dir)->mft_no, fs, &block);
    if (!mrec) {
        printf("No MFT record found!\n");
        goto out;
    }

    attr = ntfs_attr_lookup(NTFS_AT_INDEX_ROOT, mrec);
    if (!attr) {
        printf("No attribute found!\n");
        goto out;
    }

    ir = (const INDEX_ROOT *)((uint8_t *)attr +
                            attr->data.resident.value_offset);
    len = attr->data.resident.value_len;
    /* sanity check */
    if ((uint8_t *)ir + len > (uint8_t *)mrec + NTFS_SB(fs)->mft_record_size) {
        printf("Index is corrupt!\n");
        goto out;
    }

    ie = (const INDEX_ENTRY *)((uint8_t *)&ir->index +
                                ir->index.entries_offset);
    for (;; ie = (const INDEX_ENTRY *)((uint8_t *)ie + ie->len)) {
        /* bounds checks */
        if ((uint8_t *)ie < (uint8_t *)mrec ||
            (uint8_t *)ie + sizeof(INDEX_ENTRY_HEADER) >
            (uint8_t *)&ir->index + ir->index.index_len)
            goto index_err;

        /* last entry cannot contain a key */
        if (ie->flags & INDEX_ENTRY_END) {
            printf("Last entry\n");
            break;
        }

        printf("File name: ");
        print_unicode_charset(ie->key.file_name.file_name);
    }

    attr = ntfs_attr_lookup(NTFS_AT_INDEX_ALLOCATION, mrec);
    if (!attr) {
        printf("No attribute found!\n");
        goto out;
    }

    if (!attr->non_resident) {
        printf("WTF ?! $INDEX_ALLOCATION isn't really resident.\n");
        goto out;
    }

    attr_len = (uint8_t *)attr + attr->len;

    memset((void *)&chunk, 0, sizeof(chunk));
    chunk.cur_vcn = attr->data.non_resident.lowest_vcn;
    chunk.cur_lcn = 0LL;

    stream = (uint8_t *)attr + attr->data.non_resident.mapping_pairs_offset;
    offset = 0U;

    for (;;) {
        err = parse_data_run(stream, &offset, attr_len, &chunk);
        if (err)
            goto not_found;

        if (chunk.flags & MAP_UNALLOCATED)
            continue;
        if (chunk.flags & MAP_END)
            break;

        if (chunk.flags & MAP_ALLOCATED) {
            const INDEX_BLOCK *iblk;

            printf("We've got an allocated chunk...\n");

            block = chunk.cur_lcn << NTFS_SB(fs)->clust_shift;
            iblk = (const INDEX_BLOCK *)get_cache(fs->fs_dev, block);
            printf("iblk->magic = 0x%x\n", iblk->magic);
            if (iblk->magic != NTFS_MAGIC_INDX) {
                printf("Not a valid INDX record\n");
                goto out;
            }

            ie = (const INDEX_ENTRY *)((uint8_t *)&iblk->index +
                                        iblk->index.entries_offset);
            for (;; ie = (const INDEX_ENTRY *)((uint8_t *)ie + ie->len)) {
                /* bounds checks */
                if ((uint8_t *)ie < (uint8_t *)iblk || (uint8_t *)ie +
                                sizeof(INDEX_ENTRY_HEADER) >
                                (uint8_t *)&iblk->index + iblk->index.index_len)
                    goto index_err;

                /* last entry cannot contain a key */
                if (ie->flags & INDEX_ENTRY_END) {
                    printf("Last entry\n");
                    break;
                }

                /* TODO: remove this hack */
                if (!ie->key.file_name.file_name_len)
                    break;

                printf("MFT ref number: %d\n", ie->data.dir.indexed_file);
                printf("File name: ");
                print_unicode_charset(ie->key.file_name.file_name);
            }
        }
    }

    goto found; /* avoid gcc's warning */

found:
    printf("Passed :-)\n");
    inode = ntfs_inode_alloc(fs);
    return inode;

not_found:
    printf("Entry not found!\n");

out:
    return NULL;

index_err:
    printf("Corrupt index. Aborting lookup\n");
    goto out;

    /* avoid gcc's warnings */
    goto not_found;
}

static struct inode *ntfs_iget(const char *dname, struct inode *parent)
{
    return ntfs_find_entry(dname, parent);
}

static struct inode *ntfs_iget_root(struct fs_info *fs)
{
    const MFT_RECORD *mrec;
    sector_t block = 0;
    const ATTR_RECORD *attr;
    struct inode *inode = ntfs_inode_alloc(fs);
    uint32_t len;
    const INDEX_ROOT *ir;
    uint32_t clust_size;

    ntfs_printf_vol_info(fs);     /* debug */

    inode->fs = fs;

    /* look for $Root file record */
    mrec = ntfs_mft_record_lookup(FILE_root, fs, &block);
    if (!mrec) {
        printf("No MFT record found!\n");
        goto out;
    }

    NTFS_PVT(inode)->mft_no = mrec->mft_record_no;
    NTFS_PVT(inode)->seq_no = mrec->seq_no;

    NTFS_PVT(inode)->start_cluster = block >> NTFS_SB(fs)->clust_shift;
    NTFS_PVT(inode)->start = NTFS_PVT(inode)->here = block;

    /* we got the $Root file record, then look for the INDEX_ROOT attr. */
    attr = ntfs_attr_lookup(NTFS_AT_INDEX_ROOT, mrec);
    if (!attr) {
        printf("No attribute found!\n");
        goto out;
    }

    NTFS_PVT(inode)->type = attr->type;

    /* note: INDEX_ROOT is always resident */
    ir = (const INDEX_ROOT *)((uint8_t *)attr +
                                attr->data.resident.value_offset);
    len = attr->data.resident.value_len;
    if ((uint8_t *)ir + len > (uint8_t *)mrec + NTFS_SB(fs)->mft_record_size) {
        printf("Index is corrupt!\n");
        goto out;
    }

    NTFS_PVT(inode)->itype.index.collation_rule = ir->collation_rule;
    NTFS_PVT(inode)->itype.index.block_size = ir->index_block_size;
    NTFS_PVT(inode)->itype.index.block_size_shift =
                        ilog2(NTFS_PVT(inode)->itype.index.block_size);

    /* determine the size of a vcn in the index */
    clust_size = NTFS_PVT(inode)->itype.index.block_size;
    if (NTFS_SB(fs)->clust_size <= clust_size) {
        NTFS_PVT(inode)->itype.index.vcn_size = NTFS_SB(fs)->clust_size;
        NTFS_PVT(inode)->itype.index.vcn_size_shift = NTFS_SB(fs)->clust_shift;
    } else {
        NTFS_PVT(inode)->itype.index.vcn_size = BLOCK_SIZE(fs);
        NTFS_PVT(inode)->itype.index.vcn_size_shift = BLOCK_SHIFT(fs);
    }

    inode->mode = DT_DIR;

    ntfs_iget("syslinux", inode);   /* testing */
    for (;;)
        ;

    return inode;

out:
    return NULL;
}

/* Initialize the file system metadata and return block size in bits */
static int ntfs_fs_init(struct fs_info *fs)
{
    struct ntfs_bpb ntfs;
    struct ntfs_sb_info *sbi;
    struct disk *disk = fs->fs_dev->disk;

    disk->rdwr_sectors(disk, &ntfs, 0, 1, 0);

    /* sanity check */
    if (!ntfs_check_zeroed_fields(&ntfs))
        return -1;

    SECTOR_SHIFT(fs) = BLOCK_SHIFT(fs) = disk->sector_shift;
    SECTOR_SIZE(fs) = 1 << SECTOR_SHIFT(fs);
    fs->block_size = 1 << BLOCK_SHIFT(fs);

    sbi = malloc(sizeof(*sbi));
    if (!sbi)
        malloc_error("ntfs_sb_info structure");

    fs->fs_info = sbi;

    sbi->clust_shift        = ilog2(ntfs.sec_per_clust);
    sbi->clust_byte_shift   = sbi->clust_shift + SECTOR_SHIFT(fs);
    sbi->clust_mask         = ntfs.sec_per_clust - 1;
    sbi->clust_size         = ntfs.sec_per_clust << SECTOR_SHIFT(fs);
    sbi->mft_record_size    = ntfs.clust_per_mft_record <<
                                            sbi->clust_byte_shift;

    sbi->mft = ntfs.mft_lclust << sbi->clust_shift;
    /* 16 MFT entries reserved for metadata files (approximately 16 KiB) */
    sbi->mft_size = (ntfs.clust_per_mft_record << sbi->clust_shift) << 4;

    sbi->root_size = 2048;      /* temporary */
    sbi->root = sbi->mft + sbi->mft_size;
    sbi->data = sbi->root + sbi->root_size;

    sbi->clusters = (ntfs.total_sectors - sbi->data) >> sbi->clust_shift;
    if (sbi->clusters > 0xFFFFFFFFFFF4ULL)
        sbi->clusters = 0xFFFFFFFFFFF4ULL;

	/* Initialize the cache */
    cache_init(fs->fs_dev, BLOCK_SHIFT(fs));

    return BLOCK_SHIFT(fs);
}

const struct fs_ops ntfs_fs_ops = {
    .fs_name        = "ntfs",
    .fs_flags       = FS_USEMEM | FS_THISIND,
    .fs_init        = ntfs_fs_init,
    .searchdir      = NULL,
    .getfssec       = generic_getfssec,
    .close_file     = generic_close_file,
    .mangle_name    = NULL,
    .load_config    = generic_load_config,
    .readdir        = NULL,
    .iget_root      = ntfs_iget_root,
    .iget           = ntfs_iget,
    .next_extent    = ntfs_next_extent,
};
