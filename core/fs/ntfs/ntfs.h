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
 * ntfs.h - The NTFS file system structures
 */

#ifndef _NTFS_H_
#define _NTFS_H_

#include <stdint.h>

/* System defined attributes (32-bit)
 * Each attribute type has a corresponding attribute name (in Unicode)
 */
enum {
    NTFS_AT_UNUSED                      = 0x00,
    NTFS_AT_STANDARD_INFORMATION        = 0x10,
    NTFS_AT_ATTR_LIST                   = 0x20,
    NTFS_AT_FILENAME                    = 0x30,
    NTFS_AT_OBJ_ID                      = 0x40,
    NTFS_AT_SECURITY_DESCP              = 0x50,
    NTFS_AT_VOL_NAME                    = 0x60,
    NTFS_AT_VOL_INFO                    = 0x70,
    NTFS_AT_DATA                        = 0x80,
    NTFS_AT_INDEX_ROOT                  = 0x90,
    NTFS_AT_INDEX_ALLOCATION            = 0xA0,
    NTFS_AT_BITMAP                      = 0xB0,
    NTFS_AT_REPARSE_POINT               = 0xC0,
    NTFS_AT_EA_INFO                     = 0xD0,
    NTFS_AT_EA                          = 0xE0,
    NTFS_AT_PROPERTY_SET                = 0xF0,
    NTFS_AT_LOGGED_UTIL_STREAM          = 0x100,
    NTFS_AT_FIRST_USER_DEFINED_ATTR     = 0x1000,
    NTFS_AT_END                         = 0xFFFFFFFF,
};

/* NTFS File Permissions (also called attributes in DOS terminology) */
enum {
    NTFS_FILE_ATTR_READONLY                     = 0x00000001,
    NTFS_FILE_ATTR_HIDDEN                       = 0x00000002,
    NTFS_FILE_ATTR_SYSTEM                       = 0x00000004,
    NTFS_FILE_ATTR_DIRECTORY                    = 0x00000010,
    NTFS_FILE_ATTR_ARCHIVE                      = 0x00000020,
    NTFS_FILE_ATTR_DEVICE                       = 0x00000040,
    NTFS_FILE_ATTR_NORMAL                       = 0x00000080,
    NTFS_FILE_ATTR_TEMPORARY                    = 0x00000100,
    NTFS_FILE_ATTR_SPARSE_FILE                  = 0x00000200,
    NTFS_FILE_ATTR_REPARSE_POINT                = 0x00000400,
    NTFS_FILE_ATTR_COMPRESSED                   = 0x00000800,
    NTFS_FILE_ATTR_OFFLINE                      = 0x00001000,
    NTFS_FILE_ATTR_NOT_CONTENT_INDEXED          = 0x00002000,
    NTFS_FILE_ATTR_ENCRYPTED                    = 0x00004000,
    NTFS_FILE_ATTR_VALID_FLAGS                  = 0x00007FB7,
    NTFS_FILE_ATTR_VALID_SET_FLAGS              = 0x000031A7,
    NTFS_FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT  = 0x10000000,
    NTFS_FILE_ATTR_DUP_VIEW_INDEX_PRESENT       = 0x20000000,
};

/* The collation rules for sorting views/indexes/etc (32-bit) */
enum {
    NTFS_COLLATION_BINARY               = 0x00,
    NTFS_COLLATION_FILE_NAME            = 0x01,
    NTFS_COLLATION_UNICODE_STRING       = 0x02,
    NTFS_COLLATION_NTOFS_ULONG          = 0x10,
    NTFS_COLLATION_NTOFS_SID            = 0x11,
    NTFS_COLLATION_NTOFS_SECURITY_HASH  = 0x12,
    NTFS_COLLATION_NTOFS_ULONGS         = 0x13,
};

/*
 * Magic identifiers present at the beginning of all ntfs record containing
 * records (like mft records for example).
 */
enum {
    /* Found in $MFT/$DATA */
    NTFS_MAGIC_FILE     = 0x454C4946,   /* MFT entry */
    NTFS_MAGIC_INDX     = 0x58444E49,   /* Index buffer */
    NTFS_MAGIC_HOLE     = 0x454C4F48,

    /* Found in $LogFile/$DATA */
    NTFS_MAGIC_RSTR     = 0x52545352,
    NTFS_MAGIC_RCRD     = 0x44524352,
    /* Found in $LogFile/$DATA (May be found in $MFT/$DATA, also ?) */
    NTFS_MAGIC_CHKDSK   = 0x444B4843,
    /* Found in all ntfs record containing records. */
    NTFS_MAGIC_BAAD     = 0x44414142,
    NTFS_MAGIC_EMPTY    = 0xFFFFFFFF,   /* Record is empty */
};

struct ntfs_bpb {
    uint8_t jmp_boot[3];
    char oem_id[8];
    uint16_t sector_size;
    uint8_t sec_per_clust;
    uint16_t res_sectors;
    uint8_t zeroed_0[3];
    uint16_t zeroed_1;
    uint8_t media;
    uint16_t zeroed_2;
    uint16_t unused_0;
    uint16_t unused_1;
    uint32_t unused_2;
    uint32_t zeroed_3;
    uint32_t unused_3;
    uint64_t total_sectors;
    uint64_t mft_lclust;
    uint64_t mft_mirr_lclust;
    uint8_t clust_per_mft_record;
    uint8_t unused_4[3];
    uint8_t clust_per_idx_buf;
    uint8_t unused_5[3];
    uint64_t vol_serial;
    uint32_t unused_6;

    uint8_t pad[428];       /* padding to a sector boundary (512 bytes) */
} __attribute__((packed));

typedef struct {
    uint32_t magic;
    uint16_t usa_ofs;
    uint16_t usa_count;
} __attribute__((packed)) NTFS_RECORD;

/* The $MFT metadata file types */
typedef enum {
    FILE_MFT            = 0,
    FILE_MFTMirr        = 1,
    FILE_LogFile        = 2,
    FILE_Volume         = 3,
    FILE_AttrDef        = 4,
    FILE_root           = 5,
    FILE_Bitmap         = 6,
    FILE_Boot           = 7,
    FILE_BadClus        = 8,
    FILE_Secure         = 9,
    FILE_UpCase         = 10,
    FILE_Extend         = 11,
    FILE_reserved12     = 12,
    FILE_reserved13     = 13,
    FILE_reserved14     = 14,
    FILE_reserved15     = 15,
    FILE_reserved16     = 16,
} NTFS_SYSTEM_FILES;

/* MFT record flags */
enum {
    MFT_RECORD_IN_USE       = 0x0001,
    MFT_RECORD_IS_DIRECTORY = 0x0002,
} __attribute__((packed));

typedef struct {
    uint32_t magic;
    uint16_t usa_ofs;
    uint16_t usa_count;
    uint64_t lsn;
    uint16_t seq_no;
    uint16_t link_count;
    uint16_t attrs_offset;
    uint16_t flags;     /* MFT record flags */
    uint32_t bytes_in_use;
    uint32_t bytes_allocated;
    uint64_t base_mft_record;
    uint16_t next_attr_instance;
    uint16_t reserved;
    uint32_t mft_record_no;
} __attribute__((packed)) MFT_RECORD;   /* 48 bytes */

/* This is the version without the NTFS 3.1+ specific fields */
typedef struct {
    uint32_t magic;
    uint16_t usa_ofs;
    uint16_t usa_count;
    uint64_t lsn;
    uint16_t seq_no;
    uint16_t link_count;
    uint16_t attrs_offset;
    uint16_t flags;     /* MFT record flags */
    uint32_t bytes_in_use;
    uint32_t bytes_allocated;
    uint64_t base_mft_record;
    uint16_t next_attr_instance;
} __attribute__((packed)) MFT_RECORD_OLD;   /* 42 bytes */

enum {
    ATTR_DEF_INDEXABLE          = 0x02,
    ATTR_DEF_MULTIPLE           = 0x04,
    ATTR_DEF_NOT_ZERO           = 0x08,
    ATTR_DEF_INDEXED_UNIQUE     = 0x10,
    ATTR_DEF_NAMED_UNIQUE       = 0x20,
    ATTR_DEF_RESIDENT           = 0x40,
    ATTR_DEF_ALWAYS_LOG         = 0x80,
};

typedef struct {
    uint16_t name[0x40];
    uint32_t type;
    uint32_t display_rule;
    uint32_t collation_rule;
    uint32_t flags;     /* Attr def flags */
    uint64_t min_size;
    uint64_t max_size;
} __attribute__((packed)) ATTR_DEF;

/* Attribute flags (16-bit) */
enum {
    ATTR_IS_COMPRESSED      = 0x0001,
    ATTR_COMPRESSION_MASK   = 0x00FF,

    ATTR_IS_ENCRYPTED       = 0x4000,
    ATTR_IS_SPARSE          = 0x8000,
} __attribute__((packed));

/* Flags of resident attributes (8-bit) */
enum {
    RESIDENT_ATTR_IS_INDEXED = 0x01,
} __attribute__((packed));

typedef struct {
    uint32_t type;      /* Attr. type code */
    uint32_t len;
    uint8_t non_resident;
    uint8_t name_len;
    uint16_t name_offset;
    uint16_t flags;     /* Attr. flags */
    uint16_t instance;
    union {
        struct {    /* Resident attribute */
            uint32_t value_len;
            uint16_t value_offset;
            uint8_t flags;  /* Flags of resident attributes */
            int8_t reserved;
        } __attribute__((packed)) resident;
        struct {    /* Non-resident attributes */
            uint64_t lowest_vcn;
            uint64_t highest_vcn;
            uint16_t mapping_pairs_offset;
            uint8_t compression_unit;
            uint8_t reserved[5];
            int64_t allocated_size;
            int64_t initialized_size;
            int64_t compressed_size;
        } __attribute__((packed)) non_resident;
    } __attribute__((packed)) data;
} __attribute__((packed)) ATTR_RECORD;

/* Attribute: Standard Information (0x10)
 * Note: always resident
 */
typedef struct {
    int64_t ctime;
    int64_t atime;
    int64_t mtime;
    int64_t rtime;
    uint32_t file_attrs;
    union {
        struct {    /* NTFS 1.2 (48 bytes) */
            uint8_t reserved12[12];
        } __attribute__((packed)) v1;
        struct {    /* NTFS 3.x (72 bytes) */
            uint32_t max_version;
            uint32_t version;
            uint32_t class_id;
            uint32_t owner_id;
            uint32_t sec_id;
            uint64_t quota_charged;
            int64_t usn;
        } __attribute__((packed)) v3;
    } __attribute__((packed)) ver;
} __attribute__((packed)) STANDARD_INFORMATION;

/* Attribute: Attribute List (0x20)
 * Note: can be either resident or non-resident
 */
typedef struct {
    uint32_t type;
    uint16_t len;
    uint8_t name_len;
    uint8_t name_offset;
    uint64_t lowest_vcn;
    uint64_t mft_ref;
    uint16_t instance;
    uint16_t name[0];       /* Name in Unicode */
    /* sizeof() = 26 + (attribute_name_length * 2) bytes */
} __attribute__((packed)) ATTR_LIST_ENTRY;

#define NTFS_MAX_FILE_NAME_LEN 255

/* Possible namespaces for filenames in ntfs (8-bit) */
enum {
    FILE_NAME_POSIX             = 0x00,
    FILE_NAME_WIN32             = 0x01,
    FILE_NAME_DOS               = 0x02,
    FILE_NAME_WIN32_AND_DOS     = 0x03,
} __attribute__((packed));

/* Attribute: Filename (0x30)
 * Note: always resident
 */
typedef struct {
    uint64_t parent_directory;
    int64_t ctime;
    int64_t atime;
    int64_t mtime;
    int64_t rtime;
    uint64_t allocated_size;
    uint64_t data_size;
    uint32_t file_attrs;
    union {
        struct {
            uint16_t packed_ea_size;
            uint16_t reserved;      /* reserved for alignment */
        } __attribute__((packed)) ea;
        struct {
            uint32_t reparse_point_tag;
        } __attribute__((packed)) rp;
    } __attribute__((packed)) type;
    uint8_t file_name_len;
    uint8_t file_name_type;
    uint16_t file_name[0];          /* File name in Unicode */
} __attribute__((packed)) FILE_NAME_ATTR;

/* GUID structure */
typedef struct {
    uint32_t data0;
    uint16_t data1;
    uint16_t data2;
    uint8_t data3[8];
} __attribute__((packed)) GUID;

typedef struct {
    uint64_t mft_ref;
    union {
        struct {
            GUID birth_vol_id;
            GUID birth_obj_id;
            GUID domain_id;
        } __attribute__((packed)) origin;
        uint8_t extended_info[48];
    } __attribute__((packed)) opt;
} __attribute__((packed)) OBJ_ID_INDEX_DATA;

/* Attribute: Object ID (NTFS 3.0+) (0x40)
 * Note: always resident
 */
typedef struct {
    GUID object_id;
    union {
        struct {
            GUID birth_vol_id;
            GUID birth_obj_id;
            GUID domain_id;
        } __attribute__((packed)) origin;
        uint8_t extended_info[48];
    } __attribute__((packed)) opt;
} __attribute__((packed)) OBJECT_ID_ATTR;

/* Attribute: Volume Name (0x60)
 * Note: always resident
 * Note: Present only in FILE_volume
 */
typedef struct {
    uint16_t name[0];       /* The name of the volume in Unicode */
} __attribute__((packed)) VOLUME_NAME;

/* Volume flags (16-bit) */
enum {
    VOLUME_IS_DIRTY             = 0x0001,
    VOLUME_RESIZE_LOG_FILE      = 0x0002,
    VOLUME_UPGRADE_ON_MOUNT     = 0x0004,
    VOLUME_MOUNTED_ON_NT4       = 0x0008,

    VOLUME_DELETE_USN_UNDERWAY  = 0x0010,
    VOLUME_REPAIR_OBJECT_ID     = 0x0020,

    VOLUME_CHKDSK_UNDERWAY      = 0x4000,
    VOLUME_MODIFIED_BY_CHKDSK   = 0x8000,

    VOLUME_FLAGS_MASK           = 0xC03F,

    VOLUME_MUST_MOUNT_RO_MASK   = 0xC027,
} __attribute__((packed));

/* Attribute: Volume Information (0x70)
 * Note: always resident
 * Note: present only in FILE_Volume
 */
typedef struct {
    uint64_t reserved;
    uint8_t major_ver;
    uint8_t minor_ver;
    uint16_t flags;     /* Volume flags */
} __attribute__((packed)) VOLUME_INFORMATION;

/* Attribute: Data attribute (0x80)
 * Note: can be either resident or non-resident
 */
typedef struct {
    uint8_t data[0];
} __attribute__((packed)) DATA_ATTR;

/* Index header flags (8-bit) */
enum {
    SMALL_INDEX = 0,
    LARGE_INDEX = 1,
    LEAF_NODE   = 0,
    INDEX_NODE  = 1,
    NODE_MASK   = 1,
} __attribute__((packed));

/* Header for the indexes, describing the INDEX_ENTRY records, which
 * follow the INDEX_HEADER.
 */
typedef struct {
    uint32_t entries_offset;
    uint32_t index_len;
    uint32_t allocated_size;
    uint8_t flags;              /* Index header flags */
    uint8_t reserved[3];        /* Align to 8-byte boundary */
} __attribute__((packed)) INDEX_HEADER;

/* Attribute: Index Root (0x90)
 * Note: always resident
 */
typedef struct {
    uint32_t type;  /* It is $FILE_NAME for directories, zero for view indexes.
                     * No other values allowed.
                     */
    uint32_t collation_rule;
    uint32_t index_block_size;
    uint8_t clust_per_index_block;
    uint8_t reserved[3];
    INDEX_HEADER index;
} __attribute__((packed)) INDEX_ROOT;

/* Attribute: Index allocation (0xA0)
 * Note: always non-resident, of course! :-)
 */
typedef struct {
    uint32_t magic;
    uint16_t usa_ofs;           /* Update Sequence Array offsets */
    uint16_t usa_count;         /* Update Sequence Array number in bytes */
    int64_t lsn;
    int64_t index_block_vcn;    /* Virtual cluster number of the index block */
    INDEX_HEADER index;
} __attribute__((packed)) INDEX_BLOCK;

typedef INDEX_BLOCK INDEX_ALLOCATION;

enum {
    INDEX_ENTRY_HOLE            = 1,
    INDEX_ENTRY_END             = 2,
    INDEX_ENTRY_SPACE_FILTER    = 0xFFFF,
} __attribute__((packed));

typedef struct {
    union {
        struct { /* Only valid when INDEX_ENTRY_END is not set */
            uint64_t indexed_file;
        } __attribute__((packed)) dir;
        struct { /* Used for views/indexes to find the entry's data */
            uint16_t data_offset;
            uint16_t data_len;
            uint32_t reservedV;
        } __attribute__((packed)) vi;
    } __attribute__((packed)) data;
    uint16_t len;
    uint16_t key_len;
    uint16_t flags;     /* Index entry flags */
    uint16_t reserved;  /* Align to 8-byte boundary */
} __attribute__((packed)) INDEX_ENTRY_HEADER;

typedef struct {
    union {
        struct { /* Only valid when INDEX_ENTRY_END is not set */
            uint64_t indexed_file;
        } __attribute__((packed)) dir;
        struct { /* Used for views/indexes to find the entry's data */
            uint16_t data_offset;
            uint16_t data_len;
            uint32_t reservedV;
        } __attribute__((packed)) vi;
    } __attribute__((packed)) data;
    uint16_t len;
    uint16_t key_len;
    uint16_t flags;     /* Index entry flags */
    uint16_t reserved;  /* Align to 8-byte boundary */
    union {
        FILE_NAME_ATTR file_name;
        //SII_INDEX_KEY sii;
        //SDH_INDEX_KEY sdh;
        //GUID object_id;
        //REPARSE_INDEX_KEY reparse;
        //SID sid;
        uint32_t owner_id;
    } __attribute__((packed)) key;
} __attribute__((packed)) INDEX_ENTRY;

typedef struct {
    uint8_t bitmap[0];      /* Array of bits */
} __attribute__((packed)) BITMAP_ATTR;

/* The NTFS in-memory super block structure */
struct ntfs_sb_info {
    sector_t mft;                   /* The MFT region */
    sector_t root;                  /* The root dir region */
    sector_t data;                  /* The data region */

    unsigned mft_size;              /* The MFT size in sectors */
    unsigned mft_record_size;      /* MFT record size in bytes */

    uint32_t root_cluster;          /* Cluster number for (NTFS) root dir */
    int root_size;                  /* The root dir size in sectors */

    unsigned long long clusters;    /* Total number of clusters */

    unsigned clust_shift;           /* Based on sectors */
    unsigned clust_byte_shift;      /* Based on bytes */
    unsigned clust_mask;
    unsigned clust_size;

} __attribute__((packed));

static inline struct ntfs_sb_info *NTFS_SB(struct fs_info *fs)
{
    return fs->fs_info;
}

/* The NTFS in-memory inode structure */
struct ntfs_inode {
    int64_t initialized_size;
    int64_t allocated_size;
    //unsigned long state;    /* NTFS specific flags describing this inode */
    unsigned long mft_no;   /* Number of the mft record / inode */
    uint16_t seq_no;        /* Sequence number of the mft record */
    uint32_t type;          /* Attribute type of this inode */
    uint16_t *name;
    uint32_t name_len;
    uint32_t attr_list_size;
    uint8_t *attr_list;
    union {
        struct {    /* It is a directory, $MFT, or an index inode */
            uint32_t block_size;
            uint32_t vcn_size;
            uint32_t collation_rule;
            uint8_t block_size_shift;    /* log2 of the above */
            uint8_t vcn_size_shift;      /* log2 of the above */
        } index;
        struct { /* It is a compressed/sparse file/attribute inode */
            int64_t size;
            uint32_t block_size;
            uint8_t block_size_bits;
            uint8_t block_clusters;
        } compressed;
    } itype;
    uint32_t start_cluster; /* Starting cluster address */
    sector_t start;         /* Starting sector */
    sector_t offset;        /* Current sector offset */
    sector_t here;          /* Sector corresponding to offset */
};

#define NTFS_PVT(i) ((struct ntfs_inode *)((i)->pvt))

#endif /* _NTFS_H_ */
