/**
 * eCryptfs: Linux filesystem encryption layer
 * Kernel declarations.
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Trevor S. Highland <trevor.highland@gmail.com>
 *              Tyler Hicks <tyhicks@ou.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef ECRYPTFS_KERNEL_H
#define ECRYPTFS_KERNEL_H

#include <crypto/skcipher.h>
#include <keys/user-type.h>
#include <keys/encrypted-type.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/scatterlist.h>
#include <linux/hash.h>
#include <linux/nsproxy.h>
#include <linux/backing-dev.h>
#include <linux/ecryptfs.h>

extern  char CSCRYPTFS_TEST_FEK[];

#define CSCRYPTFS_FNAME_SUFFIX	".csx"
#define CSCRYPTFS_FNAME_SUFFIX_LEN 	4

#define CSCRYPTFS_EVENT_ACCESS    "00"
#define CSCRYPTFS_EVENT_READ      "01"
#define CSCRYPTFS_EVENT_WRITE     "02"
#define CSCRYPTFS_EVENT_DELETE	  "32"
#define CSCRYPTFS_EVENT_RENAME    "512"
//define CSCRYPTFS_EVENT_COPY     "256"
//#define CSCRYPTFS_EVENT_MOVE    "64"

#define CSCRYPTFS_MARKER_MAGIC_M1 0x434C4F5544534352 
#define CSCRYPTFS_MARKER_MAGIC_M2 0x45454E454E430000
#define CSCRYPTFS_MAGIC_SIZE 16
#define CSCRYPTFS_FLEN_OFFSET  204
#define CSCRYPTFS_ENT_ID_OFFSET  36
#define CSCRYPTFS_USER_ID_OFFSET 52
#define CSCRYPTFS_DEV_ID_OFFSET  60
#define CSCRYPTFS_BLK_SIZE_OFFSET 236
#define CSCRYPTFS_HLEN_OFFSET  22
#define CSCRYPTFS_TLV_OFFSET 	32


#define ECRYPTFS_DEFAULT_IV_BYTES 16
#define ECRYPTFS_DEFAULT_EXTENT_SIZE 4096
#define ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE 512
#define ECRYPTFS_DEFAULT_MSG_CTX_ELEMS 32
#define ECRYPTFS_DEFAULT_SEND_TIMEOUT HZ
#define ECRYPTFS_MAX_MSG_CTX_TTL (HZ*3)
#define ECRYPTFS_DEFAULT_NUM_USERS 4
#define ECRYPTFS_MAX_NUM_USERS 32768
#define ECRYPTFS_XATTR_NAME "user.ecryptfs"

#define CSCRYPTFS_XATTR_SIZE 	32		// 8字节长度+预留24字节

void ecryptfs_dump_auth_tok(struct ecryptfs_auth_tok *auth_tok);
static inline void
ecryptfs_to_hex(char *dst, char *src, size_t src_size)
{
	char *end = bin2hex(dst, src, src_size);
	*end = '\0';
}

extern void ecryptfs_from_hex(char *dst, char *src, int dst_size);

struct ecryptfs_crypt_stat;
struct ecryptfs_mount_crypt_stat;

struct ecryptfs_page_crypt_context {
	struct page *page;
#define ECRYPTFS_PREPARE_COMMIT_MODE 0
#define ECRYPTFS_WRITEPAGE_MODE      1
	unsigned int mode;
	union {
		struct file *lower_file;
		struct writeback_control *wbc;
	} param;
};

#define ECRYPTFS_MAX_KEYSET_SIZE 1024
#define ECRYPTFS_MAX_CIPHER_NAME_SIZE 31
#define ECRYPTFS_MAX_NUM_ENC_KEYS 64
#define ECRYPTFS_MAX_IV_BYTES 16	/* 128 bits */
#define ECRYPTFS_SALT_BYTES 2
#define MAGIC_ECRYPTFS_MARKER 0x3c81b7f5
#define MAGIC_ECRYPTFS_MARKER_SIZE_BYTES 8	/* 4*2 */
#define ECRYPTFS_FILE_SIZE_BYTES (sizeof(u64))
#define ECRYPTFS_SIZE_AND_MARKER_BYTES (ECRYPTFS_FILE_SIZE_BYTES \
					+ MAGIC_ECRYPTFS_MARKER_SIZE_BYTES)
#define ECRYPTFS_CIPHER_FILE_MARKER_SIZE 16 // For our encrypted file marker

#define ECRYPTFS_DEFAULT_CIPHER "aes"
#define ECRYPTFS_DEFAULT_KEY_BYTES 16
#define ECRYPTFS_DEFAULT_HASH "md5"

/* Constraint: ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES >=
 * ECRYPTFS_MAX_IV_BYTES */
#define ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES 16
#define ECRYPTFS_NON_NULL 0x42 /* A reasonable substitute for NULL */
#define MD5_DIGEST_SIZE 16

#define ECRYPTFS_ENCRYPTED_DENTRY_NAME_LEN (18 + 1 + 4 + 1 + 32)

#define ECRYPTFS_VERSIONING_MASK (ECRYPTFS_VERSIONING_PASSPHRASE \
				  | ECRYPTFS_VERSIONING_PLAINTEXT_PASSTHROUGH \
				  | ECRYPTFS_VERSIONING_XATTR \
				  | ECRYPTFS_VERSIONING_MULTKEY \
				  | ECRYPTFS_VERSIONING_FILENAME_ENCRYPTION)

/**
 * This is the primary struct associated with each encrypted file.
 *
 * TODO: cache align/pack?
 */
struct ecryptfs_crypt_stat {
#define ECRYPTFS_STRUCT_INITIALIZED   0x00000001
#define ECRYPTFS_POLICY_APPLIED       0x00000002
#define ECRYPTFS_ENCRYPTED            0x00000004
#define ECRYPTFS_SECURITY_WARNING     0x00000008
#define ECRYPTFS_ENABLE_HMAC          0x00000010
#define ECRYPTFS_ENCRYPT_IV_PAGES     0x00000020
#define ECRYPTFS_KEY_VALID            0x00000040
#define ECRYPTFS_METADATA_IN_XATTR    0x00000080
#define ECRYPTFS_KEY_SET              0x00000200
#define ECRYPTFS_ENCRYPT_FILENAMES    0x00000400
#define ECRYPTFS_ENCFN_USE_MOUNT_FNEK 0x00000800
#define ECRYPTFS_ENCFN_USE_FEK        0x00001000
#define ECRYPTFS_UNLINK_SIGS          0x00002000
#define ECRYPTFS_I_SIZE_INITIALIZED   0x00004000
#define ECRYPTFS_FOPEN_CREDIT         0x00008000
	u32 flags;
	unsigned int file_version;
	size_t iv_bytes;
	size_t metadata_size;
	size_t extent_size; /* Data extent size; default is 4096 */
	size_t key_size;
	size_t extent_shift;
	unsigned int extent_mask;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct crypto_skcipher *tfm;
	struct crypto_shash *hash_tfm; /* Crypto context for generating
					* the initialization vectors */
	unsigned char cipher[ECRYPTFS_MAX_CIPHER_NAME_SIZE + 1];
	unsigned char key[ECRYPTFS_MAX_KEY_BYTES];
	unsigned char root_iv[ECRYPTFS_MAX_IV_BYTES];
	struct list_head keysig_list;
	struct mutex keysig_list_mutex;
	struct mutex cs_tfm_mutex;
	struct mutex cs_mutex;
};

/* inode private data. */
struct ecryptfs_inode_info {
	struct inode vfs_inode;
	struct inode *wii_inode;
	struct mutex lower_file_mutex;
	atomic_t lower_file_count;
	struct file *lower_file;
	struct ecryptfs_crypt_stat crypt_stat;
};

/* dentry private data. Each dentry must keep track of a lower
 * vfsmount too. */
struct ecryptfs_dentry_info {
	struct path lower_path;
	union {
		struct ecryptfs_crypt_stat *crypt_stat;
		struct rcu_head rcu;
	};
};

/**
 * ecryptfs_key_tfm - Persistent key tfm
 * @key_tfm: crypto API handle to the key
 * @key_size: Key size in bytes
 * @key_tfm_mutex: Mutex to ensure only one operation in eCryptfs is
 *                 using the persistent TFM at any point in time
 * @cipher_name: String name for the cipher for this TFM
 *
 * Typically, eCryptfs will use the same ciphers repeatedly throughout
 * the course of its operations. In order to avoid unnecessarily
 * destroying and initializing the same cipher repeatedly, eCryptfs
 * keeps a list of crypto API contexts around to use when needed.
 */
struct ecryptfs_key_tfm {
	struct crypto_skcipher *key_tfm;
	size_t key_size;
	struct mutex key_tfm_mutex;
	unsigned char cipher_name[ECRYPTFS_MAX_CIPHER_NAME_SIZE + 1];
};

extern struct ecryptfs_key_tfm *cipher_key_tfm;

#define FILE_MAX_EXT_LEN        8
#define EXT_MAX_CREDIT_NUM      4
struct credit_app {
	char ext[FILE_MAX_EXT_LEN];                    // 文件后缀名类别
	char comms[EXT_MAX_CREDIT_NUM][TASK_COMM_LEN]; // 可信进程task名称
};

#define MAX_EXT_ENTRYS        8

struct ecryptfs_enterprise_stat {
	int login;
	unsigned char key[ECRYPTFS_DEFAULT_KEY_BYTES];
	u64 enterprise_id;
	u64 user_id;
	u64 device_id;
	int entrys_num;
	struct credit_app credit_entrys[MAX_EXT_ENTRYS];
};

extern struct ecryptfs_enterprise_stat enterprise_stat;

/**
 * This struct is to enable a mount-wide passphrase/salt combo. This
 * is more or less a stopgap to provide similar functionality to other
 * crypto filesystems like EncFS or CFS until full policy support is
 * implemented in eCryptfs.
 */

#define MNT_CRYPT_STAT_MAGIC    0x43534653 			//CSFS
struct ecryptfs_mount_crypt_stat {
	u32 magic;
	/* Pointers to memory we do not own, do not free these */
#define ECRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED  0x00000001
#define CSCRYPTFS_USER_LOGIN                   0x00000002
	u32 flags;
	struct list_head mount_crypt_stat_list;
	size_t global_default_cipher_key_size;
	char global_default_cipher_name[ECRYPTFS_MAX_CIPHER_NAME_SIZE + 1];
	struct ecryptfs_key_tfm *cipher_tfm;

	struct mutex mux;
	const char *mount_path;		//文件系统挂载点
	u64 enterprise_id;		//企业ID
	u64 user_id;					
	u64 device_id;
	int entrys_num;
	struct credit_app  credit_entrys[MAX_EXT_ENTRYS];
};

/* superblock private data. */
struct ecryptfs_sb_info {
	struct super_block *wsi_sb;
	struct ecryptfs_mount_crypt_stat mount_crypt_stat;
};

/* file private data. */
struct ecryptfs_file_info {
	#define CSCRYPTFS_FILE_ENCRYPTED	 0x00000001
	#define CSCRYPTFS_FOPEN_CREDIBLE 	 0x00000002  //授信的文件打开行为
	#define CSCRYPTFS_NEW_FILE_CARED 	 0x00000004  //需要关注新建文件打开
	#define CSCRYPTFS_FILE_WRITTEN 	 	 0x00000008 
	#define CSCRYPTFS_FILE_READ              0x00000010
	#define CSCRYPTFS_FOPEN_NOCREDIBLE       0x00000020
	u32 flags;
	struct file *wfi_file;
	struct ecryptfs_crypt_stat *crypt_stat;
};

static inline size_t
ecryptfs_lower_header_size(struct ecryptfs_crypt_stat *crypt_stat)
{
	return crypt_stat->metadata_size;
}

static inline struct ecryptfs_file_info *
ecryptfs_file_to_private(struct file *file)
{
	return file->private_data;
}

static inline void
ecryptfs_set_file_private(struct file *file,
			  struct ecryptfs_file_info *file_info)
{
	file->private_data = file_info;
}

static inline struct file *ecryptfs_file_to_lower(struct file *file)
{
	return ((struct ecryptfs_file_info *)file->private_data)->wfi_file;
}

static inline void
ecryptfs_set_file_lower(struct file *file, struct file *lower_file)
{
	((struct ecryptfs_file_info *)file->private_data)->wfi_file =
		lower_file;
}

static inline struct ecryptfs_inode_info *
ecryptfs_inode_to_private(struct inode *inode)
{
	return container_of(inode, struct ecryptfs_inode_info, vfs_inode);
}

static inline struct inode *ecryptfs_inode_to_lower(struct inode *inode)
{
	return ecryptfs_inode_to_private(inode)->wii_inode;
}

static inline void
ecryptfs_set_inode_lower(struct inode *inode, struct inode *lower_inode)
{
	ecryptfs_inode_to_private(inode)->wii_inode = lower_inode;
}

static inline struct ecryptfs_sb_info *
ecryptfs_superblock_to_private(struct super_block *sb)
{
	return (struct ecryptfs_sb_info *)sb->s_fs_info;
}

static inline void
ecryptfs_set_superblock_private(struct super_block *sb,
				struct ecryptfs_sb_info *sb_info)
{
	sb->s_fs_info = sb_info;
}

static inline struct super_block *
ecryptfs_superblock_to_lower(struct super_block *sb)
{
	return ((struct ecryptfs_sb_info *)sb->s_fs_info)->wsi_sb;
}

static inline void
ecryptfs_set_superblock_lower(struct super_block *sb,
			      struct super_block *lower_sb)
{
	((struct ecryptfs_sb_info *)sb->s_fs_info)->wsi_sb = lower_sb;
}

static inline struct ecryptfs_dentry_info *
ecryptfs_dentry_to_private(struct dentry *dentry)
{
	return (struct ecryptfs_dentry_info *)dentry->d_fsdata;
}

static inline void
ecryptfs_set_dentry_private(struct dentry *dentry,
			    struct ecryptfs_dentry_info *dentry_info)
{
	dentry->d_fsdata = dentry_info;
}

static inline struct dentry *
ecryptfs_dentry_to_lower(struct dentry *dentry)
{
	return ((struct ecryptfs_dentry_info *)dentry->d_fsdata)->lower_path.dentry;
}

static inline struct vfsmount *
ecryptfs_dentry_to_lower_mnt(struct dentry *dentry)
{
	return ((struct ecryptfs_dentry_info *)dentry->d_fsdata)->lower_path.mnt;
}

static inline struct path *
ecryptfs_dentry_to_lower_path(struct dentry *dentry)
{
	return &((struct ecryptfs_dentry_info *)dentry->d_fsdata)->lower_path;
}

static inline struct ecryptfs_mount_crypt_stat*
ecryptfs_get_mount_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat)
{
	struct inode *inode = 
		&container_of(crypt_stat, struct ecryptfs_inode_info, 
			     crypt_stat)->vfs_inode;
	return &((struct ecryptfs_sb_info *)(inode->i_sb->s_fs_info))->mount_crypt_stat;
}

#define ecryptfs_printk(type, fmt, arg...) \
        __ecryptfs_printk(type "%s: " fmt, __func__, ## arg);
__printf(1, 2)
void __ecryptfs_printk(const char *fmt, ...);

extern const struct file_operations ecryptfs_main_fops;
extern const struct file_operations ecryptfs_dir_fops;
extern const struct inode_operations ecryptfs_main_iops;
extern const struct inode_operations ecryptfs_dir_iops;
extern const struct inode_operations ecryptfs_symlink_iops;
extern const struct super_operations ecryptfs_sops;
extern const struct dentry_operations ecryptfs_dops;
extern const struct address_space_operations ecryptfs_aops;
extern int ecryptfs_verbosity;
extern unsigned int ecryptfs_message_buf_len;
extern signed long ecryptfs_message_wait_timeout;
extern unsigned int ecryptfs_number_of_users;

extern struct kmem_cache *ecryptfs_auth_tok_list_item_cache;
extern struct kmem_cache *ecryptfs_file_info_cache;
extern struct kmem_cache *ecryptfs_dentry_info_cache;
extern struct kmem_cache *ecryptfs_inode_info_cache;
extern struct kmem_cache *ecryptfs_sb_info_cache;
extern struct kmem_cache *ecryptfs_header_cache;
extern struct kmem_cache *ecryptfs_path_cache;

extern struct list_head mount_crypt_stat_list;
extern struct mutex mount_crypt_stat_list_mutex;

struct inode *ecryptfs_get_inode(struct inode *lower_inode,
				 struct super_block *sb);
void ecryptfs_i_size_init(const char *page_virt, struct inode *inode);
int ecryptfs_initialize_file(struct dentry *ecryptfs_dentry,
			     struct inode *ecryptfs_inode);
int ecryptfs_decode_and_decrypt_filename(char **decrypted_name,
					 size_t *decrypted_name_size,
					 struct super_block *sb,
					 const char *name, size_t name_size);
int ecryptfs_fill_zeros(struct file *file, loff_t new_length);

struct dentry *ecryptfs_lower_dentry(struct dentry *this_dentry);
void ecryptfs_dump_hex(char *data, int bytes);
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
			int sg_size);
int ecryptfs_compute_root_iv(struct ecryptfs_crypt_stat *crypt_stat);
void ecryptfs_rotate_iv(unsigned char *iv);
int ecryptfs_init_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat);
void ecryptfs_destroy_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat);
void ecryptfs_destroy_mount_crypt_stat(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat);
int ecryptfs_init_crypt_ctx(struct ecryptfs_crypt_stat *crypt_stat);
int ecryptfs_write_inode_size_to_metadata(struct inode *ecryptfs_inode);
int ecryptfs_encrypt_page(struct page *page);
int ecryptfs_decrypt_page(struct page *page);
int ecryptfs_write_metadata(struct dentry *ecryptfs_dentry,
			    struct inode *ecryptfs_inode);
int ecryptfs_read_metadata(struct dentry *ecryptfs_dentry);
int ecryptfs_new_file_context(struct inode *ecryptfs_inode);

int ecryptfs_read_and_validate_header_region(struct dentry *dentry, 
					     struct inode *inode);
u8 ecryptfs_code_for_cipher_string(char *cipher_name, size_t key_bytes);
int ecryptfs_cipher_code_to_string(char *str, u8 cipher_code);
void ecryptfs_set_default_sizes(struct ecryptfs_crypt_stat *crypt_stat);
int ecryptfs_truncate(struct dentry *dentry, loff_t newecryptfs_derive_iv_length);
ssize_t
ecryptfs_getxattr_lower(struct dentry *lower_dentry, struct inode *lower_inode,
			const char *name, void *value, size_t size);
int
ecryptfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
		  const void *value, size_t size, int flags);

void
ecryptfs_write_header_metadata(char *virt,
			       struct ecryptfs_crypt_stat *crypt_stat,
			       size_t *written);
int
ecryptfs_create_key_tfm(struct ecryptfs_key_tfm **key_tfm, char *cipher_name,
			 size_t key_size);
int ecryptfs_write_lower(struct inode *ecryptfs_inode, char *data,
			 loff_t offset, size_t size);
int ecryptfs_write_lower_page_segment(struct inode *ecryptfs_inode,
				      struct page *page_for_lower,
				      size_t offset_in_page, size_t size);
int ecryptfs_write(struct inode *inode, char *data, loff_t offset, size_t size);
int ecryptfs_read_lower(char *data, loff_t offset, size_t size,
			struct inode *ecryptfs_inode);
int ecryptfs_read_lower_page_segment(struct page *page_for_ecryptfs,
				     pgoff_t page_index,
				     size_t offset_in_page, size_t size,
				     struct inode *ecryptfs_inode);
struct page *ecryptfs_get_locked_page(struct inode *inode, loff_t index);
int ecryptfs_parse_packet_length(unsigned char *data, size_t *size,
				 size_t *length_size);
int ecryptfs_write_packet_length(char *dest, size_t size,
				 size_t *packet_size_length);
int ecryptfs_init_kthread(void);
void ecryptfs_destroy_kthread(void);
int ecryptfs_privileged_open(struct file **lower_file,
			     struct dentry *lower_dentry,
			     struct vfsmount *lower_mnt,
			     const struct cred *cred);
int ecryptfs_get_lower_file(struct dentry *dentry, struct inode *inode);
void ecryptfs_put_lower_file(struct inode *inode);
int ecryptfs_set_f_namelen(long *namelen, long lower_namelen,
			   struct ecryptfs_mount_crypt_stat *mount_crypt_stat);
int ecryptfs_derive_iv(char *iv, struct ecryptfs_crypt_stat *crypt_stat,
		       loff_t offset);

extern const struct xattr_handler *ecryptfs_xattr_handlers[];

// 可信任进程处理函数
static inline int 
filename_suffixed_with_csx(struct qstr *dname) 
{
	return (dname->len > CSCRYPTFS_FNAME_SUFFIX_LEN 
			&& !strcmp(dname->name + dname->len - CSCRYPTFS_FNAME_SUFFIX_LEN, CSCRYPTFS_FNAME_SUFFIX));
}
int is_encrypt_file(struct dentry *ecryptfs_dentry,
			  struct inode *ecryptfs_inode);
struct qstr *dup_enterprise_dentry_name_off_csx(struct qstr *dname);
void free_enterprise_dentry_name(struct qstr *dname);
int app_behavior_credible(u64 enterprise_id, struct qstr *dname, 
			  struct ecryptfs_mount_crypt_stat *mount_crypt_stat);
int file_ext_need_attention(struct qstr *dname, 
			    struct ecryptfs_mount_crypt_stat *mount_crypt_stat);
int report_undo_enterprise_file(int suspected, 
				u64 last_modify, 
				const char *fpath);
char *ecryptfs_dentry_fullpath(const char *mount_point, struct dentry *dentry,
			       char *buf, int buflen);
int report_enterprise_file_event(const char *tag, u64 last_modify, 
				 const char *fpath);
int report_enterprise_file_rename(u64 last_modify, const char *old_fpath, 
				  const char *new_fpath);

int cscryptfs_netlink_init(void);
void cscryptfs_netlink_exit(void);

int
send_netlink_msg(void *buf, int size, int portid, int seq, int cmd, int attr);

int encryptfs_enterprise_init(void);
int encryptfs_enterprise_save(void);

void 
encryptfs_enterprise_parse(struct ecryptfs_mount_crypt_stat *mount_crypt_stat);

// stat系列系统调用
typedef asmlinkage long (*sys_stat_t)(const char __user *filename, 
			 struct stat __user *statbuf);
typedef asmlinkage long (*sys_lstat_t)(const char __user *filename, 
			 struct stat __user *statbuf);
typedef asmlinkage long (*sys_fstat_t)(unsigned int fd, 
			 struct stat __user *statbuf);
extern asmlinkage long cs_stat(const char __user *filename, 
			 struct stat __user *statbuf);
extern asmlinkage long cs_lstat(const char __user *filename, 
			 struct stat __user *statbuf);
extern asmlinkage long cs_fstat(unsigned int fd, struct stat __user *statbuf);
extern sys_stat_t old_stat;
extern sys_lstat_t old_lstat;
extern sys_fstat_t old_fstat;
#endif /* #ifndef ECRYPTFS_KERNEL_H */
