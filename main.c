/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
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

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/skbuff.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/parser.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/magic.h>
#include "ecryptfs_kernel.h"

/**
 * Module parameter that defines the ecryptfs_verbosity level.
 */
int ecryptfs_verbosity = 1;

module_param(ecryptfs_verbosity, int, 0);
MODULE_PARM_DESC(ecryptfs_verbosity,
		 "Initial verbosity level (0 or 1; defaults to "
		 "0, which is Quiet)");

/**
 * Module parameter that defines the number of message buffer elements
 */
unsigned int ecryptfs_message_buf_len = ECRYPTFS_DEFAULT_MSG_CTX_ELEMS;

module_param(ecryptfs_message_buf_len, uint, 0);
MODULE_PARM_DESC(ecryptfs_message_buf_len,
		 "Number of message buffer elements");

/**
 * Module parameter that defines the maximum guaranteed amount of time to wait
 * for a response from ecryptfsd.  The actual sleep time will be, more than
 * likely, a small amount greater than this specified value, but only less if
 * the message successfully arrives.
 */
signed long ecryptfs_message_wait_timeout = ECRYPTFS_MAX_MSG_CTX_TTL / HZ;

module_param(ecryptfs_message_wait_timeout, long, 0);
MODULE_PARM_DESC(ecryptfs_message_wait_timeout,
		 "Maximum number of seconds that an operation will "
		 "sleep while waiting for a message response from "
		 "userspace");

/**
 * Module parameter that is an estimate of the maximum number of users
 * that will be concurrently using eCryptfs. Set this to the right
 * value to balance performance and memory use.
 */
unsigned int ecryptfs_number_of_users = ECRYPTFS_DEFAULT_NUM_USERS;

module_param(ecryptfs_number_of_users, uint, 0);
MODULE_PARM_DESC(ecryptfs_number_of_users, "An estimate of the number of "
		 "concurrent users of eCryptfs");

void __ecryptfs_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (fmt[1] == '7') { /* KERN_DEBUG */
		if (ecryptfs_verbosity >= 1)
			vprintk(fmt, args);
	} else
		vprintk(fmt, args);
	va_end(args);
}

/**
 * ecryptfs_init_lower_file
 * @ecryptfs_dentry: Fully initialized eCryptfs dentry object, with
 *                   the lower dentry and the lower mount set
 *
 * eCryptfs only ever keeps a single open file for every lower
 * inode. All I/O operations to the lower inode occur through that
 * file. When the first eCryptfs dentry that interposes with the first
 * lower dentry for that inode is created, this function creates the
 * lower file struct and associates it with the eCryptfs
 * inode. When all eCryptfs files associated with the inode are released, the
 * file is closed.
 *
 * The lower file will be opened with read/write permissions, if
 * possible. Otherwise, it is opened read-only.
 *
 * This function does nothing if a lower file is already
 * associated with the eCryptfs inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_init_lower_file(struct dentry *dentry,
				    struct file **lower_file)
{
	const struct cred *cred = current_cred();
	struct path *path = ecryptfs_dentry_to_lower_path(dentry);
	int rc;

	rc = ecryptfs_privileged_open(lower_file, path->dentry, path->mnt,
				      cred);
	if (rc) {
		printk(KERN_ERR "Error opening lower file "
		       "for lower_dentry [0x%p] and lower_mnt [0x%p]; "
		       "rc = [%d]\n", path->dentry, path->mnt, rc);
		(*lower_file) = NULL;
	}
	return rc;
}

// 同一inode对象关联一个底层的low_file对象, 无论获取几次
int ecryptfs_get_lower_file(struct dentry *dentry, struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;
	int count, rc = 0;

	inode_info = ecryptfs_inode_to_private(inode);
	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	if (WARN_ON_ONCE(count < 1))
		rc = -EINVAL;
	else if (count == 1) {
		rc = ecryptfs_init_lower_file(dentry,
					      &inode_info->lower_file);
		if (rc)
			atomic_set(&inode_info->lower_file_count, 0);
	}
	mutex_unlock(&inode_info->lower_file_mutex);
	return rc;
}

// 底层file对象引用数减一，如果引用计数为0,那么将缓存数据写入底层文件
void ecryptfs_put_lower_file(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;

	inode_info = ecryptfs_inode_to_private(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
				      &inode_info->lower_file_mutex)) {
		// 没有引用底层文件对象的inode对象,因此将缓存区数据写入底层文件并关闭底层文件
		filemap_write_and_wait(inode->i_mapping);
		fput(inode_info->lower_file);
		inode_info->lower_file = NULL;
		mutex_unlock(&inode_info->lower_file_mutex);
	}
}

enum {
       ecryptfs_opt_cipher, ecryptfs_opt_ecryptfs_cipher,
       ecryptfs_opt_ecryptfs_key_bytes,
       ecryptfs_opt_passthrough,
       ecryptfs_opt_encrypted_view,
       ecryptfs_opt_unlink_sigs,
       ecryptfs_opt_check_dev_ruid,
       ecryptfs_opt_err };

static const match_table_t tokens = {
	{ecryptfs_opt_cipher, "cipher=%s"},
	{ecryptfs_opt_ecryptfs_cipher, "ecryptfs_cipher=%s"},
	{ecryptfs_opt_ecryptfs_key_bytes, "ecryptfs_key_bytes=%u"},
	{ecryptfs_opt_passthrough, "ecryptfs_passthrough"},
	{ecryptfs_opt_encrypted_view, "ecryptfs_encrypted_view"},
	{ecryptfs_opt_unlink_sigs, "ecryptfs_unlink_sigs"},
	{ecryptfs_opt_check_dev_ruid, "ecryptfs_check_dev_ruid"},
	{ecryptfs_opt_err, NULL}
};

static void ecryptfs_init_mount_crypt_stat(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	memset((void *)mount_crypt_stat, 0,
	       sizeof(struct ecryptfs_mount_crypt_stat));
	mount_crypt_stat->flags |= ECRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED;
}

/**
 * ecryptfs_parse_options
 * @sb: The ecryptfs super block
 * @options: The options passed to the kernel
 * @check_ruid: set to 1 if device uid should be checked against the ruid
 *
 * Parse mount options:
 * debug=N 	   - ecryptfs_verbosity level for debug output
 * sig=XXX	   - description(signature) of the key to use
 *
 * Returns the dentry object of the lower-level (lower/interposed)
 * directory; We want to mount our stackable file system on top of
 * that lower directory.
 *
 * The signature of the key to use must be the description of a key
 * already in the keyring. Mounting will fail if the key can not be
 * found.
 *
 * Returns zero on success; non-zero on error
 */
static int ecryptfs_parse_options(struct ecryptfs_sb_info *sbi, char *options,
				  uid_t *check_ruid)
{
	char *p;
	int rc = 0;
	int cipher_name_set = 0;
	int cipher_key_bytes;
	int cipher_key_bytes_set = 0;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&sbi->mount_crypt_stat;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *cipher_name_dst;
	char *cipher_name_src;
	char *cipher_key_bytes_src;
	u8 cipher_code;

	*check_ruid = 0;

	if (!options) {
		ecryptfs_printk(KERN_DEBUG, "No mount options input\n");
	}
	ecryptfs_init_mount_crypt_stat(mount_crypt_stat);
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case ecryptfs_opt_cipher:
		case ecryptfs_opt_ecryptfs_cipher:
			cipher_name_src = args[0].from;
			cipher_name_dst =
				mount_crypt_stat->global_default_cipher_name;
			strncpy(cipher_name_dst, cipher_name_src,
				ECRYPTFS_MAX_CIPHER_NAME_SIZE);
			cipher_name_dst[ECRYPTFS_MAX_CIPHER_NAME_SIZE] = '\0';
			cipher_name_set = 1;
			break;
		case ecryptfs_opt_ecryptfs_key_bytes:
			cipher_key_bytes_src = args[0].from;
			cipher_key_bytes =
				(int)simple_strtol(cipher_key_bytes_src,
						   &cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_cipher_key_size =
				cipher_key_bytes;
			cipher_key_bytes_set = 1;
			break;
		case ecryptfs_opt_unlink_sigs:
			mount_crypt_stat->flags |= ECRYPTFS_UNLINK_SIGS;
			break;
		case ecryptfs_opt_check_dev_ruid:
			*check_ruid = 1;
			break;
		case ecryptfs_opt_err:
		default:
			printk(KERN_WARNING
			       "%s: eCryptfs: unrecognized option [%s]\n",
			       __func__, p);
		}
	}
	if (!cipher_name_set) {
		int cipher_name_len = strlen(ECRYPTFS_DEFAULT_CIPHER);

		BUG_ON(cipher_name_len > ECRYPTFS_MAX_CIPHER_NAME_SIZE);
		strcpy(mount_crypt_stat->global_default_cipher_name,
		       ECRYPTFS_DEFAULT_CIPHER);
	}
	if (!cipher_key_bytes_set)
		mount_crypt_stat->global_default_cipher_key_size = 16;

	cipher_code = ecryptfs_code_for_cipher_string(
		mount_crypt_stat->global_default_cipher_name,
		mount_crypt_stat->global_default_cipher_key_size);
	if (!cipher_code) {
		ecryptfs_printk(KERN_ERR,
				"eCryptfs doesn't support cipher: %s\n",
				mount_crypt_stat->global_default_cipher_name);
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}

struct kmem_cache *ecryptfs_sb_info_cache;
static struct file_system_type ecryptfs_fs_type;


struct list_head mount_crypt_stat_list;
struct mutex mount_crypt_stat_list_mutex;

struct ecryptfs_key_tfm *cipher_key_tfm;

static int __init ecryptfs_init_mount_list(void)
{
	mutex_init(&mount_crypt_stat_list_mutex);
	INIT_LIST_HEAD(&mount_crypt_stat_list);
	return 0;
}

static int ecryptfs_destroy_mount_list(void)
{
	mutex_lock(&mount_crypt_stat_list_mutex);
	if(!list_empty(&mount_crypt_stat_list)) {
		ecryptfs_printk(KERN_ERR, "mount_crypt_stat_list not"
					  "empty when destroying\n");
		//TODO
		//卸载文件系统时, list正确因该为空
	} else {
		ecryptfs_printk(KERN_DEBUG, "mount_crypt_stat_list empty" 
					    "when destroying\n");
	}
	mutex_unlock(&mount_crypt_stat_list_mutex);
	return 0;
}
/**
 * ecryptfs_get_sb
 * @fs_type
 * @flags
 * @dev_name: The path to mount over
 * @raw_data: The options passed into the kernel
 */
static struct dentry *ecryptfs_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *raw_data)
{
	struct super_block *s;
	struct ecryptfs_sb_info *sbi;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_dentry_info *root_info;
	const char *err = "Getting sb failed";
	struct inode *inode;
	struct path path;
	uid_t check_ruid;
	int rc;

	sbi = kmem_cache_zalloc(ecryptfs_sb_info_cache, GFP_KERNEL);
	if (!sbi) {
		rc = -ENOMEM;
		goto out;
	}

	rc = ecryptfs_parse_options(sbi, raw_data, &check_ruid);
	if (rc) {
		err = "Error parsing options";
		goto out;
	}
	mount_crypt_stat = &sbi->mount_crypt_stat;
	mount_crypt_stat->cipher_tfm = cipher_key_tfm; // 每个挂载点共享同一个

	s = sget(fs_type, NULL, set_anon_super, flags, NULL);
	if (IS_ERR(s)) {
		rc = PTR_ERR(s);
		goto out;
	}

	rc = super_setup_bdi(s);
	if (rc)
		goto out1;

	ecryptfs_set_superblock_private(s, sbi);

	/* ->kill_sb() will take care of sbi after that point */
	sbi = NULL;
	s->s_op = &ecryptfs_sops;
	s->s_xattr = ecryptfs_xattr_handlers;
	s->s_d_op = &ecryptfs_dops;

	err = "Reading sb failed";
	rc = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "kern_path() failed\n");
		goto out1;
	}
	ecryptfs_printk(KERN_DEBUG, "fstype name: %s", 
			path.dentry->d_sb->s_type->name);
	if (path.dentry->d_sb->s_type == &ecryptfs_fs_type) {
		rc = -EINVAL;
		printk(KERN_ERR "Mount on filesystem of type "
			"eCryptfs explicitly disallowed due to "
			"known incompatibilities\n");
		goto out_free;
	}

	if (check_ruid && !uid_eq(d_inode(path.dentry)->i_uid, current_uid())) {
		rc = -EPERM;
		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
		       "requested user (uid: %d)\n",
			i_uid_read(d_inode(path.dentry)),
			from_kuid(&init_user_ns, current_uid()));
		goto out_free;
	}

	ecryptfs_set_superblock_lower(s, path.dentry->d_sb);

	/**
	 * Set the POSIX ACL flag based on whether they're enabled in the lower
	 * mount.
	 */
	s->s_flags = flags & ~SB_POSIXACL;
	s->s_flags |= path.dentry->d_sb->s_flags & SB_POSIXACL;

	/**
	 * Force a read-only eCryptfs mount when:
	 *   1) The lower mount is ro
	 *   2) The ecryptfs_encrypted_view mount option is specified
	 */
	if (sb_rdonly(path.dentry->d_sb))
		s->s_flags |= SB_RDONLY;

	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
	s->s_blocksize = path.dentry->d_sb->s_blocksize;
	s->s_magic = ECRYPTFS_SUPER_MAGIC;
	s->s_stack_depth = path.dentry->d_sb->s_stack_depth + 1;

	rc = -EINVAL;
	if (s->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("eCryptfs: maximum fs stacking depth exceeded\n");
		goto out_free;
	}

	inode = ecryptfs_get_inode(d_inode(path.dentry), s);
	rc = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_free;

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		rc = -ENOMEM;
		goto out_free;
	}

	rc = -ENOMEM;
	root_info = kmem_cache_zalloc(ecryptfs_dentry_info_cache, GFP_KERNEL);
	if (!root_info)
		goto out_free;

	/* ->kill_sb() will take care of root_info */
	ecryptfs_set_dentry_private(s->s_root, root_info);
	root_info->lower_path = path;

	s->s_flags |= SB_ACTIVE;
	return dget(s->s_root);

out_free:
	path_put(&path);
out1:
	deactivate_locked_super(s);
out:
	if (sbi) {
		ecryptfs_destroy_mount_crypt_stat(&sbi->mount_crypt_stat);
		kmem_cache_free(ecryptfs_sb_info_cache, sbi);
	}
	printk(KERN_ERR "%s; rc = [%d]\n", err, rc);
	return ERR_PTR(rc);
}

/**
 * ecryptfs_kill_block_super
 * @sb: The ecryptfs super block
 *
 * Used to bring the superblock down and free the private data.
 */
static void ecryptfs_kill_block_super(struct super_block *sb)
{
	struct ecryptfs_sb_info *sb_info = ecryptfs_superblock_to_private(sb);
	kill_anon_super(sb);
	if (!sb_info)
		return;
	ecryptfs_destroy_mount_crypt_stat(&sb_info->mount_crypt_stat);
	kmem_cache_free(ecryptfs_sb_info_cache, sb_info);
}

static struct file_system_type ecryptfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "csecryptfs",
	.mount = ecryptfs_mount,
	.kill_sb = ecryptfs_kill_block_super,
	.fs_flags = 0
};
MODULE_ALIAS_FS("csecryptfs");

/**
 * inode_info_init_once
 *
 * Initializes the ecryptfs_inode_info_cache when it is created
 */
static void
inode_info_init_once(void *vptr)
{
	struct ecryptfs_inode_info *ei = (struct ecryptfs_inode_info *)vptr;

	inode_init_once(&ei->vfs_inode);
}

struct kmem_cache *ecryptfs_path_cache;

static struct ecryptfs_cache_info {
	struct kmem_cache **cache;
	const char *name;
	size_t size;
	slab_flags_t flags;
	void (*ctor)(void *obj);
} ecryptfs_cache_infos[] = {
	{
		.cache = &ecryptfs_file_info_cache,
		.name = "ecryptfs_file_cache",
		.size = sizeof(struct ecryptfs_file_info),
	},
	{
		.cache = &ecryptfs_dentry_info_cache,
		.name = "ecryptfs_dentry_info_cache",
		.size = sizeof(struct ecryptfs_dentry_info),
	},
	{
		.cache = &ecryptfs_inode_info_cache,
		.name = "ecryptfs_inode_cache",
		.size = sizeof(struct ecryptfs_inode_info),
		.flags = SLAB_ACCOUNT,
		.ctor = inode_info_init_once,
	},
	{
		.cache = &ecryptfs_sb_info_cache,
		.name = "ecryptfs_sb_cache",
		.size = sizeof(struct ecryptfs_sb_info),
	},
	{
		.cache = &ecryptfs_header_cache,
		.name = "ecryptfs_headers",
		.size = PAGE_SIZE,
	},
	{
		.cache = &ecryptfs_path_cache,
		.name = "ecryptfs_path",
		.size = PATH_MAX,
	}
};

static void ecryptfs_free_kmem_caches(void)
{
	int i;

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	for (i = 0; i < ARRAY_SIZE(ecryptfs_cache_infos); i++) {
		struct ecryptfs_cache_info *info;

		info = &ecryptfs_cache_infos[i];
		kmem_cache_destroy(*(info->cache));
	}
}

/**
 * ecryptfs_init_kmem_caches
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_init_kmem_caches(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ecryptfs_cache_infos); i++) {
		struct ecryptfs_cache_info *info;

		info = &ecryptfs_cache_infos[i];
		*(info->cache) = kmem_cache_create(info->name, info->size, 0,
				SLAB_HWCACHE_ALIGN | info->flags, info->ctor);
		if (!*(info->cache)) {
			ecryptfs_free_kmem_caches();
			ecryptfs_printk(KERN_WARNING, "%s: "
					"kmem_cache_create failed\n",
					info->name);
			return -ENOMEM;
		}
	}
	return 0;
}

static struct kobject *ecryptfs_kobj;

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return snprintf(buff, PAGE_SIZE, "%d\n", ECRYPTFS_VERSIONING_MASK);
}

static struct kobj_attribute version_attr = __ATTR_RO(version);

static struct attribute *attributes[] = {
	&version_attr.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = attributes,
};

static int do_sysfs_registration(void)
{
	int rc;

	ecryptfs_kobj = kobject_create_and_add("csecryptfs", fs_kobj);
	if (!ecryptfs_kobj) {
		printk(KERN_ERR "Unable to create ecryptfs kset\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = sysfs_create_group(ecryptfs_kobj, &attr_group);
	if (rc) {
		printk(KERN_ERR
		       "Unable to create ecryptfs version attributes\n");
		kobject_put(ecryptfs_kobj);
	}
out:
	return rc;
}

static void do_sysfs_unregistration(void)
{
	sysfs_remove_group(ecryptfs_kobj, &attr_group);
	kobject_put(ecryptfs_kobj);
}

sys_stat_t old_stat = NULL;
sys_lstat_t old_lstat = NULL;
sys_fstat_t old_fstat = NULL;

static uintptr_t *syscall = NULL;

#define CR0_WRITE_PROTECT 0x10000

static uint64_t get_cr0(void)
{
	uint64_t ret;

	__asm__ volatile (
		"movq %%cr0, %[ret]"
		: [ret] "=r" (ret)
	);
	return ret;
}

static void set_cr0(uint64_t cr0)
{
	__asm__ volatile (
		"movq %[cr0], %%cr0"
		:
		: [cr0] "r" (cr0)
	);
}

static uintptr_t set_hook(int syscall_id, uintptr_t hookfunc)
{
	uintptr_t oldfunc = syscall[syscall_id];
	set_cr0(get_cr0() & ~CR0_WRITE_PROTECT);
	syscall[syscall_id] = hookfunc;	
	set_cr0(get_cr0() | CR0_WRITE_PROTECT);
	return oldfunc;
}

static int __init ecryptfs_init(void)
{
	int rc;

	if (ECRYPTFS_DEFAULT_EXTENT_SIZE > PAGE_SIZE) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "The eCryptfs extent size is "
				"larger than the host's page size, and so "
				"eCryptfs cannot run on this system. The "
				"default eCryptfs extent size is [%u] bytes; "
				"the page size is [%lu] bytes.\n",
				ECRYPTFS_DEFAULT_EXTENT_SIZE,
				(unsigned long)PAGE_SIZE);
		goto out;
	}
	rc = ecryptfs_init_kmem_caches();
	if (rc) {
		printk(KERN_ERR
		       "Failed to allocate one or more kmem_cache objects\n");
		goto out;
	}
	rc = do_sysfs_registration();
	if (rc) {
		printk(KERN_ERR "sysfs registration failed\n");
		goto out_free_kmem_caches;
	}
	rc = ecryptfs_init_kthread();
	if (rc) {
		printk(KERN_ERR "%s: kthread initialization failed; "
		       "rc = [%d]\n", __func__, rc);
		goto out_do_sysfs_unregistration;
	}
	rc = cscryptfs_netlink_init();
	if (rc) {
		printk(KERN_ERR "Failure to init cscryptfs netlink\n");
		goto out_destroy_kthread;
	}
	rc = register_filesystem(&ecryptfs_fs_type);
	if (rc) {
		printk(KERN_ERR "Failed to register filesystem\n");
		goto out_destroy_netlink;
	}

	rc = ecryptfs_create_key_tfm(&cipher_key_tfm, "aes", 16);
	if (rc) {
		printk(KERN_ERR "Failed to Create crypto_skcipher\n");
		goto out_unregister_filesystem;
	}

	ecryptfs_init_mount_list();
	encryptfs_enterprise_init();

	syscall = (uintptr_t *) kallsyms_lookup_name("sys_call_table");
	old_stat =  (sys_stat_t)set_hook(__NR_stat, (uintptr_t)cs_stat);
 	old_lstat = (sys_lstat_t)set_hook(__NR_lstat, (uintptr_t)cs_lstat);
 	old_fstat = (sys_fstat_t)set_hook(__NR_fstat, (uintptr_t)cs_fstat);
	printk("hook stat:%lx, lstat:%lx, fstat:%lx\n",  
		syscall[__NR_sendto],  
		syscall[__NR_lstat],  
		syscall[__NR_fstat]);

	if (ecryptfs_verbosity > 0)
		printk(KERN_CRIT "eCryptfs verbosity set to %d. Secret values "
			"will be written to the syslog!\n", ecryptfs_verbosity);

	goto out;

out_unregister_filesystem:
	unregister_filesystem(&ecryptfs_fs_type);
out_destroy_netlink:
	cscryptfs_netlink_exit();
out_destroy_kthread:
	ecryptfs_destroy_kthread();
out_do_sysfs_unregistration:
	do_sysfs_unregistration();
out_free_kmem_caches:
	ecryptfs_free_kmem_caches();
out:
	return rc;
}

static void __exit ecryptfs_exit(void)
{
	set_hook(__NR_stat, (uintptr_t)old_stat);
	set_hook(__NR_lstat, (uintptr_t)old_lstat);
	set_hook(__NR_fstat, (uintptr_t)old_fstat);

	ecryptfs_destroy_mount_list();
	cscryptfs_netlink_exit();
	ecryptfs_destroy_kthread();
	do_sysfs_unregistration();
	unregister_filesystem(&ecryptfs_fs_type);
	ecryptfs_free_kmem_caches();
	printk("unload csCryptfs success\n");
}

MODULE_AUTHOR("yan wen <mhalcrow@us.ibm.com>");
MODULE_DESCRIPTION("cseCryptfs");

MODULE_LICENSE("GPL");

module_init(ecryptfs_init)
module_exit(ecryptfs_exit)
