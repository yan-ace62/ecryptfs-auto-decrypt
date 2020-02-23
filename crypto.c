/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *   		Michael C. Thompson <mcthomps@us.ibm.com>
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

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/key.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include <linux/kernel.h>
#include "ecryptfs_kernel.h"
#include "netlink.h"

char CSCRYPTFS_TEST_FEK[] = "\xd3\x1c\x5c\x23\x42\x08\x49\x07"
			    "\xa2\xee\xf9\x4d\xf0\x67\xbc\x9d";

#define DECRYPT		0
#define ENCRYPT		1

/**
 * ecryptfs_from_hex
 * @dst: Buffer to take the bytes from src hex; must be at least of
 *       size (src_size / 2)
 * @src: Buffer to be converted from a hex string representation to raw value
 * @dst_size: size of dst buffer, or number of hex characters pairs to convert
 */
void ecryptfs_from_hex(char *dst, char *src, int dst_size)
{
	int x;
	char tmp[3] = { 0, };

	for (x = 0; x < dst_size; x++) {
		tmp[0] = src[x * 2];
		tmp[1] = src[x * 2 + 1];
		dst[x] = (unsigned char)simple_strtol(tmp, NULL, 16);
	}
}

static int ecryptfs_hash_digest(struct crypto_shash *tfm,
				char *src, int len, char *dst)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;

	desc->tfm = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	err = crypto_shash_digest(desc, src, len, dst);
	shash_desc_zero(desc);
	return err;
}

/**
 * ecryptfs_calculate_md5 - calculates the md5 of @src
 * @dst: Pointer to 16 bytes of allocated memory
 * @crypt_stat: Pointer to crypt_stat struct for the current inode
 * @src: Data to be md5'd
 * @len: Length of @src
 *
 * Uses the allocated crypto context that crypt_stat references to
 * generate the MD5 sum of the contents of src.
 */
static int ecryptfs_calculate_md5(char *dst,
				  struct ecryptfs_crypt_stat *crypt_stat,
				  char *src, int len)
{
	struct crypto_shash *tfm;
	int rc = 0;

	tfm = crypt_stat->hash_tfm;
	rc = ecryptfs_hash_digest(tfm, src, len, dst);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error computing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
out:
	return rc;
}

static int ecryptfs_crypto_api_algify_cipher_name(char **algified_name,
						  char *cipher_name,
						  char *chaining_modifier)
{
	int cipher_name_len = strlen(cipher_name);
	int chaining_modifier_len = strlen(chaining_modifier);
	int algified_name_len;
	int rc;

	algified_name_len = (chaining_modifier_len + cipher_name_len + 3);
	(*algified_name) = kmalloc(algified_name_len, GFP_KERNEL);
	if (!(*algified_name)) {
		rc = -ENOMEM;
		goto out;
	}
	snprintf((*algified_name), algified_name_len, "%s(%s)",
		 chaining_modifier, cipher_name);
	ecryptfs_printk(KERN_DEBUG, "cpher name: %s\n", *algified_name);
	rc = 0;
out:
	return rc;
}

/**
 * ecryptfs_derive_iv
 * @iv: destination for the derived iv vale
 * @crypt_stat: Pointer to crypt_stat struct for the current inode
 * @offset: Offset of the extent whose IV we are to derive
 *
 * Generate the initialization vector from the given root IV and page offset.
 *
 * Returns zero on success; non-zero on error.
 */
int ecryptfs_derive_iv(char *iv, struct ecryptfs_crypt_stat *crypt_stat,
		       loff_t offset)
{
	int rc = 0;
	char dst[MD5_DIGEST_SIZE];
	char src[ECRYPTFS_MAX_IV_BYTES + 16];

	// if (unlikely(ecryptfs_verbosity > 0)) {
		// ecryptfs_printk(KERN_DEBUG, "root iv:\n");
		// ecryptfs_dump_hex(crypt_stat->root_iv, crypt_stat->iv_bytes);
	// }
	/* TODO: It is probably secure to just cast the least
	 * significant bits of the root IV into an unsigned long and
	 * add the offset to that rather than go through all this
	 * hashing business. -Halcrow */
	memcpy(src, crypt_stat->root_iv, crypt_stat->iv_bytes);
	memset((src + crypt_stat->iv_bytes), 0, 16);
	snprintf((src + crypt_stat->iv_bytes), 16, "%lld", offset);
	// if (unlikely(ecryptfs_verbosity > 0)) {
	// 	ecryptfs_printk(KERN_DEBUG, "source:\n");
	// 	ecryptfs_dump_hex(src, (crypt_stat->iv_bytes + 16));
	// }
	rc = ecryptfs_calculate_md5(dst, crypt_stat, src,
				    (crypt_stat->iv_bytes + 16));
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to compute "
				"MD5 while generating IV for a page\n");
		goto out;
	}
	memcpy(iv, dst, crypt_stat->iv_bytes);
	// if (unlikely(ecryptfs_verbosity > 0)) {
	// 	ecryptfs_printk(KERN_DEBUG, "derived iv:\n");
	// 	ecryptfs_dump_hex(iv, crypt_stat->iv_bytes);
	// }
out:
	return rc;
}

/**
 * ecryptfs_init_crypt_stat
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 *
 * Initialize the crypt_stat structure.
 */
int ecryptfs_init_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = crypto_alloc_shash(ECRYPTFS_DEFAULT_HASH, 0, 0);
	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		ecryptfs_printk(KERN_ERR, "Error attempting to "
				"allocate crypto context; rc = [%d]\n",
				rc);
		return rc;
	}

	memset((void *)crypt_stat, 0, sizeof(struct ecryptfs_crypt_stat));
	mutex_init(&crypt_stat->cs_mutex);
	mutex_init(&crypt_stat->cs_tfm_mutex);
	crypt_stat->hash_tfm = tfm;
	crypt_stat->flags |= ECRYPTFS_STRUCT_INITIALIZED;

	return 0;
}

/**
 * ecryptfs_destroy_crypt_stat
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 *
 * Releases all memory associated with a crypt_stat struct.
 */
void ecryptfs_destroy_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat)
{

	// crypto_free_skcipher(crypt_stat->tfm); //所有文件加解密共享同一个skcipher
	crypto_free_shash(crypt_stat->hash_tfm);
	memset(crypt_stat, 0, sizeof(struct ecryptfs_crypt_stat));
}

void ecryptfs_destroy_mount_crypt_stat(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	if (!(mount_crypt_stat->flags & ECRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED))
		return;
	memset(mount_crypt_stat, 0, sizeof(struct ecryptfs_mount_crypt_stat));
}

/**
 * virt_to_scatterlist
 * @addr: Virtual address
 * @size: Size of data; should be an even multiple of the block size
 * @sg: Pointer to scatterlist array; set to NULL to obtain only
 *      the number of scatterlist structs required in array
 * @sg_size: Max array size
 *
 * Fills in a scatterlist array with page references for a passed
 * virtual address.
 *
 * Returns the number of scatterlist structs in array used
 */
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
			int sg_size)
{
	int i = 0;
	struct page *pg;
	int offset;
	int remainder_of_page;

	sg_init_table(sg, sg_size);

	while (size > 0 && i < sg_size) {
		pg = virt_to_page(addr);
		offset = offset_in_page(addr);
		sg_set_page(&sg[i], pg, 0, offset);
		remainder_of_page = PAGE_SIZE - offset;
		if (size >= remainder_of_page) {
			sg[i].length = remainder_of_page;
			addr += remainder_of_page;
			size -= remainder_of_page;
		} else {
			sg[i].length = size;
			addr += size;
			size = 0;
		}
		i++;
	}
	if (size > 0)
		return -ENOMEM;
	return i;
}

struct extent_crypt_result {
	struct completion completion;
	int rc;
};

static void extent_crypt_complete(struct crypto_async_request *req, int rc)
{
	struct extent_crypt_result *ecr = req->data;

	if (rc == -EINPROGRESS)
		return;

	ecr->rc = rc;
	complete(&ecr->completion);
}

/**
 * crypt_scatterlist
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 * @dst_sg: Destination of the data after performing the crypto operation
 * @src_sg: Data to be encrypted or decrypted
 * @size: Length of data
 * @iv: IV to use
 * @op: ENCRYPT or DECRYPT to indicate the desired operation
 *
 * Returns the number of bytes encrypted or decrypted; negative value on error
 */
static int crypt_scatterlist(struct ecryptfs_crypt_stat *crypt_stat,
			     struct scatterlist *dst_sg,
			     struct scatterlist *src_sg, int size,
			     unsigned char *iv, int op)
{
	struct skcipher_request *req = NULL;
	struct extent_crypt_result ecr;
	int rc = 0;

	// TODO 创建crypt_stat->tfm对象
	BUG_ON(!crypt_stat || !crypt_stat->tfm
	       || !(crypt_stat->flags & ECRYPTFS_STRUCT_INITIALIZED));
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "Key size [%zd]; key:\n",
				crypt_stat->key_size);
		ecryptfs_dump_hex(crypt_stat->key, crypt_stat->key_size);
	}

	// 线程(进程)之间的同步大多使用completion，而互斥资源的保护大多使用信号量(互斥锁or自旋锁)
	init_completion(&ecr.completion);

	mutex_lock(&crypt_stat->cs_tfm_mutex);
	req = skcipher_request_alloc(crypt_stat->tfm, GFP_NOFS);
	if (!req) {
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		rc = -ENOMEM;
		goto out;
	}

	// 设置加解密请求回调数据,更新req.base.complete, req.base.data, req.base.flags
	skcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			extent_crypt_complete, &ecr);
	/* Consider doing this once, when the file is opened */
	if (!(crypt_stat->flags & ECRYPTFS_KEY_SET)) { // 如果加密秘钥还没设置好，那么设置加密秘钥
		rc = crypto_skcipher_setkey(crypt_stat->tfm, crypt_stat->key,
					    crypt_stat->key_size);
		if (rc) {
			ecryptfs_printk(KERN_ERR,
					"Error setting key; rc = [%d]\n",
					rc);
			mutex_unlock(&crypt_stat->cs_tfm_mutex);
			rc = -EINVAL;
			goto out;
		}
		crypt_stat->flags |= ECRYPTFS_KEY_SET;
	}
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	// This function allows setting of the source data and destination data
 	// scatter / gather lists.
	skcipher_request_set_crypt(req, src_sg, dst_sg, size, iv);
	// 发起加解密操作
	rc = op == ENCRYPT ? crypto_skcipher_encrypt(req) :
			     crypto_skcipher_decrypt(req);
	if (rc == -EINPROGRESS || rc == -EBUSY) {
		struct extent_crypt_result *ecr = req->base.data;

		wait_for_completion(&ecr->completion);
		rc = ecr->rc;
		reinit_completion(&ecr->completion);
	}
out:
	skcipher_request_free(req);
	return rc;
}

/**
 * lower_offset_for_page
 *
 * Convert an eCryptfs page index into a lower byte offset
 */
static loff_t lower_offset_for_page(struct ecryptfs_crypt_stat *crypt_stat,
				    struct page *page)
{
	return ecryptfs_lower_header_size(crypt_stat) +
	       ((loff_t)page->index << PAGE_SHIFT);
}

/**
 * crypt_extent
 * @crypt_stat: crypt_stat containing cryptographic context for the
 *              encryption operation
 * @dst_page: The page to write the result into
 * @src_page: The page to read from
 * @extent_offset: Page extent offset for use in generating IV
 * @op: ENCRYPT or DECRYPT to indicate the desired operation
 *
 * Encrypts or decrypts one extent of data.
 *
 * Return zero on success; non-zero otherwise
 */
static int crypt_extent(struct ecryptfs_crypt_stat *crypt_stat,
			struct page *dst_page,
			struct page *src_page,
			unsigned long extent_offset, int op)
{
	pgoff_t page_index = op == ENCRYPT ? src_page->index : dst_page->index;
	loff_t extent_base;
	char extent_iv[ECRYPTFS_MAX_IV_BYTES];
	struct scatterlist src_sg, dst_sg;
	size_t extent_size = crypt_stat->extent_size; // default 4096
	int rc;

	extent_base = (((loff_t)page_index) * (PAGE_SIZE / extent_size));
	// 随机生成iv
	rc = ecryptfs_derive_iv(extent_iv, crypt_stat,
				(extent_base + extent_offset));
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error attempting to derive IV for "
			"extent [0x%.16llx]; rc = [%d]\n",
			(unsigned long long)(extent_base + extent_offset), rc);
		goto out;
	}

	sg_init_table(&src_sg, 1);
	sg_init_table(&dst_sg, 1);

	sg_set_page(&src_sg, src_page, extent_size,extent_offset * extent_size);
	sg_set_page(&dst_sg, dst_page, extent_size,extent_offset * extent_size);

	// 加解密的实际操作在这里(针对每一个需要的页缓存)
	rc = crypt_scatterlist(crypt_stat, &dst_sg, &src_sg, extent_size,
			       extent_iv, op);
	if (rc < 0) {
		printk(KERN_ERR "%s: Error attempting to crypt page with "
		       "page_index = [%ld], extent_offset = [%ld]; "
		       "rc = [%d]\n", __func__, page_index, extent_offset, rc);
		goto out;
	}
	rc = 0;
out:
	return rc;
}

/**
 * ecryptfs_encrypt_page
 * @page: Page mapped from the eCryptfs inode for the file; contains
 *        decrypted content that needs to be encrypted (to a temporary
 *        page; not in place) and written out to the lower file
 *
 * Encrypt an eCryptfs page. This is done on a per-extent basis. Note
 * that eCryptfs pages may straddle the lower pages -- for instance,
 * if the file was created on a machine with an 8K page size
 * (resulting in an 8K header), and then the file is copied onto a
 * host with a 32K page size, then when reading page 0 of the eCryptfs
 * file, 24K of page 0 of the lower file will be read and decrypted,
 * and then 8K of page 1 of the lower file will be read and decrypted.
 *
 * Returns zero on success; negative on error
 */
int ecryptfs_encrypt_page(struct page *page)
{
	struct inode *ecryptfs_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *enc_extent_virt;
	struct page *enc_extent_page = NULL;
	loff_t extent_offset;
	loff_t lower_offset;
	int rc = 0;

	ecryptfs_inode = page->mapping->host;
	crypt_stat =
		&(ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat);
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));
	enc_extent_page = alloc_page(GFP_USER);
	if (!enc_extent_page) {
		rc = -ENOMEM;
		ecryptfs_printk(KERN_ERR, "Error allocating memory for "
				"encrypted extent\n");
		goto out;
	}

	for (extent_offset = 0;
	     extent_offset < (PAGE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		rc = crypt_extent(crypt_stat, enc_extent_page, page,
				  extent_offset, ENCRYPT);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting extent; "
			       "rc = [%d]\n", __func__, rc);
			goto out;
		}
	}

	lower_offset = lower_offset_for_page(crypt_stat, page);
	enc_extent_virt = kmap(enc_extent_page);
	rc = ecryptfs_write_lower(ecryptfs_inode, enc_extent_virt, lower_offset,
				  PAGE_SIZE);
	kunmap(enc_extent_page);
	if (rc < 0) {
		ecryptfs_printk(KERN_ERR,
			"Error attempting to write lower page; rc = [%d]\n",
			rc);
		goto out;
	}
	rc = 0;
out:
	if (enc_extent_page) {
		__free_page(enc_extent_page);
	}
	return rc;
}

/**
 * ecryptfs_decrypt_page
 * @page: Page mapped from the eCryptfs inode for the file; data read and 
 *        decrypted from the lower file will be written into this page
 *
 * Decrypt an eCryptfs page. This is done on a per-extent basis. Note
 * that eCryptfs pages may straddle the lower pages -- for instance,
 * if the file was created on a machine with an 8K page size
 * (resulting in an 8K header), and then the file is copied onto a
 * host with a 32K page size, then when reading page 0 of the eCryptfs
 * file, 24K of page 0 of the lower file will be read and decrypted,
 * and then 8K of page 1 of the lower file will be read and decrypted.
 *
 * Returns zero on success; negative on error
 */
int ecryptfs_decrypt_page(struct page *page)
{
	struct inode *ecryptfs_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *page_virt;
	unsigned long extent_offset;
	loff_t lower_offset;
	int rc = 0;

	ecryptfs_inode = page->mapping->host;
	crypt_stat =
		&(ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat);
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));

	// 每次读取文件时候将偏移量加上head_size
	lower_offset = lower_offset_for_page(crypt_stat, page);
	page_virt = kmap(page);
	rc = ecryptfs_read_lower(page_virt, lower_offset, PAGE_SIZE,
				 ecryptfs_inode);
	kunmap(page);
	if (rc < 0) {
		ecryptfs_printk(KERN_ERR,
			"Error attempting to read lower page; rc = [%d]\n",
			rc);
		goto out;
	}

	for (extent_offset = 0;
	     extent_offset < (PAGE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		rc = crypt_extent(crypt_stat, page, page,
				  extent_offset, DECRYPT);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting extent; "
			       "rc = [%d]\n", __func__, rc);
			goto out;
		}
	}
out:
	return rc;
}

#define ECRYPTFS_MAX_SCATTERLIST_LEN 4

/**
 * ecryptfs_init_crypt_ctx
 * @crypt_stat: Uninitialized crypt stats structure
 *
 * Initialize the crypto context.
 *
 * TODO: Performance: Keep a cache of initialized cipher contexts;
 * only init if needed
 */
int ecryptfs_init_crypt_ctx(struct ecryptfs_crypt_stat *crypt_stat)
{
	char *full_alg_name;
	int rc = -EINVAL;

	ecryptfs_printk(KERN_DEBUG,
			"Initializing cipher [%s]; strlen = [%d]; "
			"key_size_bits = [%zd]\n",
			crypt_stat->cipher, (int)strlen(crypt_stat->cipher),
			crypt_stat->key_size << 3);
	mutex_lock(&crypt_stat->cs_tfm_mutex);
	if (crypt_stat->tfm) {
		rc = 0;
		goto out_unlock;
	}
	rc = ecryptfs_crypto_api_algify_cipher_name(&full_alg_name,
						    crypt_stat->cipher, "ecb");
	if (rc)
		goto out_unlock;
	crypt_stat->tfm = crypto_alloc_skcipher(full_alg_name, 0, 0);
	if (IS_ERR(crypt_stat->tfm)) {
		rc = PTR_ERR(crypt_stat->tfm);
		crypt_stat->tfm = NULL;
		ecryptfs_printk(KERN_ERR, "cryptfs: init_crypt_ctx(): "
				"Error initializing cipher [%s]\n",
				full_alg_name);
		goto out_free;
	}
	crypto_skcipher_set_flags(crypt_stat->tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	rc = 0;
out_free:
	kfree(full_alg_name);
out_unlock:
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	return rc;
}

// 如果extent_size设置为偶数, 那么extent_mask=oxFFFFFFFF, extent_shift=0
static void set_extent_mask_and_shift(struct ecryptfs_crypt_stat *crypt_stat)
{
	int extent_size_tmp;

	crypt_stat->extent_mask = 0xFFFFFFFF;
	crypt_stat->extent_shift = 0;
	if (crypt_stat->extent_size == 0)
		return;
	extent_size_tmp = crypt_stat->extent_size; // default 4096
	while ((extent_size_tmp & 0x01) == 0) { // 奇数偶数判断
		extent_size_tmp >>= 1;
		crypt_stat->extent_mask <<= 1;
		crypt_stat->extent_shift++;
	}
}

void ecryptfs_set_default_sizes(struct ecryptfs_crypt_stat *crypt_stat)
{
	/* Default values; may be overwritten as we are parsing the packets. */
	crypt_stat->extent_size = ECRYPTFS_DEFAULT_EXTENT_SIZE;
	set_extent_mask_and_shift(crypt_stat);
	crypt_stat->iv_bytes = ECRYPTFS_DEFAULT_IV_BYTES;
	crypt_stat->metadata_size = ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE;

}

/**
 * ecryptfs_compute_root_iv
 * @crypt_stats
 *
 * On error, sets the root IV to all 0's.
 */
int ecryptfs_compute_root_iv(struct ecryptfs_crypt_stat *crypt_stat)
{
	int rc = 0;
	char dst[MD5_DIGEST_SIZE];

	BUG_ON(crypt_stat->iv_bytes > MD5_DIGEST_SIZE);
	BUG_ON(crypt_stat->iv_bytes <= 0);
	if (!(crypt_stat->flags & ECRYPTFS_KEY_VALID)) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_WARNING, "Session key not valid; "
				"cannot generate root IV\n");
		goto out;
	}
	rc = ecryptfs_calculate_md5(dst, crypt_stat, crypt_stat->key,
				    crypt_stat->key_size);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to compute "
				"MD5 while generating root IV\n");
		goto out;
	}
	memcpy(crypt_stat->root_iv, dst, crypt_stat->iv_bytes);
out:
	if (rc) {
		memset(crypt_stat->root_iv, 0, crypt_stat->iv_bytes);
		crypt_stat->flags |= ECRYPTFS_SECURITY_WARNING;
	}
	return rc;
}

static void ecryptfs_generate_new_key(struct ecryptfs_crypt_stat *crypt_stat)
{
	//get_random_bytes(crypt_stat->key, crypt_stat->key_size);
	memcpy(crypt_stat->key, CSCRYPTFS_TEST_FEK, 16);
	crypt_stat->flags |= ECRYPTFS_KEY_VALID;
	ecryptfs_compute_root_iv(crypt_stat);
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "Generated new session key:\n");
		ecryptfs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}
}

/**
 * ecryptfs_copy_mount_wide_flags_to_inode_flags
 * @crypt_stat: The inode's cryptographic context
 * @mount_crypt_stat: The mount point's cryptographic context
 *
 * This function propagates the mount-wide flags to individual inode
 * flags.
 */
static void ecryptfs_copy_mount_wide_flags_to_inode_flags(
	struct ecryptfs_crypt_stat *crypt_stat,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{

}

/**
 * ecryptfs_set_default_crypt_stat_vals
 * @crypt_stat: The inode's cryptographic context
 * @mount_crypt_stat: The mount point's cryptographic context
 *
 * Default values in the event that policy does not override them.
 */
static void ecryptfs_set_default_crypt_stat_vals(
	struct ecryptfs_crypt_stat *crypt_stat,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	ecryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	ecryptfs_set_default_sizes(crypt_stat);
	strcpy(crypt_stat->cipher, ECRYPTFS_DEFAULT_CIPHER);
	crypt_stat->key_size = ECRYPTFS_DEFAULT_KEY_BYTES;
	crypt_stat->flags &= ~(ECRYPTFS_KEY_VALID);
	crypt_stat->file_version = ECRYPTFS_FILE_VERSION;
	crypt_stat->mount_crypt_stat = mount_crypt_stat;
}

/**
 * ecryptfs_new_file_context
 * @ecryptfs_inode: The eCryptfs inode
 *
 * If the crypto context for the file has not yet been established,
 * this is where we do that.  Establishing a new crypto context
 * involves the following decisions:
 *  - What cipher to use?
 *  - What set of authentication tokens to use?
 * Here we just worry about getting enough information into the
 * authentication tokens so that we know that they are available.
 * We associate the available authentication tokens with the new file
 * via the set of signatures in the crypt_stat struct.  Later, when
 * the headers are actually written out, we may again defer to
 * userspace to perform the encryption of the session key; for the
 * foreseeable future, this will be the case with public key packets.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_new_file_context(struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat =
	    &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
	    &ecryptfs_superblock_to_private(
		    ecryptfs_inode->i_sb)->mount_crypt_stat;
	int cipher_name_len;
	int rc = 0;

	ecryptfs_set_default_crypt_stat_vals(crypt_stat, mount_crypt_stat);
	crypt_stat->flags |= (ECRYPTFS_ENCRYPTED | ECRYPTFS_KEY_VALID);
	ecryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	if (rc) {
		printk(KERN_ERR "Error attempting to copy mount-wide key sigs "
		       "to the inode key sigs; rc = [%d]\n", rc);
		goto out;
	}
	cipher_name_len =
		strlen(mount_crypt_stat->global_default_cipher_name);
	memcpy(crypt_stat->cipher,
	       mount_crypt_stat->global_default_cipher_name,
	       cipher_name_len);
	crypt_stat->cipher[cipher_name_len] = '\0';
	crypt_stat->key_size =
		mount_crypt_stat->global_default_cipher_key_size;
	// 初始化加密上下文与秘钥与初始化向量相关的数据
	ecryptfs_generate_new_key(crypt_stat);
	rc = ecryptfs_init_crypt_ctx(crypt_stat);
	if (rc)
		ecryptfs_printk(KERN_ERR, "Error initializing cryptographic "
				"context for cipher [%s]: rc = [%d]\n",
				crypt_stat->cipher, rc);
out:
	return rc;
}

/**
 * ecryptfs_validate_marker - check for the ecryptfs marker
 * @data: The data block in which to check
 *
 * Returns zero if marker found; -EINVAL if not found
 */
static int ecryptfs_validate_marker(char *data)
{
	u64 m_1, m_2;

	m_1 = get_unaligned_be64(data);
	m_2 = get_unaligned_be64(data + 8);
	ecryptfs_printk(KERN_DEBUG, "m_1 = [0x%llx]; m_2 = [0x%llx]\n", m_1, m_2);
	if (m_1 == CSCRYPTFS_MARKER_MAGIC_M1 && m_2 == CSCRYPTFS_MARKER_MAGIC_M2) {
		ecryptfs_printk(KERN_DEBUG, "check cs metadata magic success\n");
		return 0;
	}
	return -EINVAL;
}

/**
 * write_ecryptfs_marker
 * @page_virt: The pointer to in a page to begin writing the marker
 * @written: Number of bytes written
 *
 * Marker = 0x3c81b7f5
 */
static void write_ecryptfs_marker(char *page_virt, size_t *written)
{
	u64 m_1 = CSCRYPTFS_MARKER_MAGIC_M1, m_2 = CSCRYPTFS_MARKER_MAGIC_M2;
	put_unaligned_be64(m_1, page_virt);
	put_unaligned_be64(m_2, page_virt + 8);
}

struct ecryptfs_cipher_code_str_map_elem {
	char cipher_str[16];
	u8 cipher_code;
};

/* Add support for additional ciphers by adding elements here. The
 * cipher_code is whatever OpenPGP applications use to identify the
 * ciphers. List in order of probability. */
static struct ecryptfs_cipher_code_str_map_elem
ecryptfs_cipher_code_str_map[] = {
	{"aes",RFC2440_CIPHER_AES_128 },
	{"blowfish", RFC2440_CIPHER_BLOWFISH},
	{"des3_ede", RFC2440_CIPHER_DES3_EDE},
	{"cast5", RFC2440_CIPHER_CAST_5},
	{"twofish", RFC2440_CIPHER_TWOFISH},
	{"cast6", RFC2440_CIPHER_CAST_6},
	{"aes", RFC2440_CIPHER_AES_192},
	{"aes", RFC2440_CIPHER_AES_256}
};

/**
 * ecryptfs_code_for_cipher_string
 * @cipher_name: The string alias for the cipher
 * @key_bytes: Length of key in bytes; used for AES code selection
 *
 * Returns zero on no match, or the cipher code on match
 */
u8 ecryptfs_code_for_cipher_string(char *cipher_name, size_t key_bytes)
{
	int i;
	u8 code = 0;
	struct ecryptfs_cipher_code_str_map_elem *map =
		ecryptfs_cipher_code_str_map;

	if (strcmp(cipher_name, "aes") == 0) {
		switch (key_bytes) {
		case 16:
			code = RFC2440_CIPHER_AES_128;
			break;
		case 24:
			code = RFC2440_CIPHER_AES_192;
			break;
		case 32:
			code = RFC2440_CIPHER_AES_256;
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(ecryptfs_cipher_code_str_map); i++)
			if (strcmp(cipher_name, map[i].cipher_str) == 0) {
				code = map[i].cipher_code;
				break;
			}
	}
	return code;
}

/**
 * ecryptfs_cipher_code_to_string
 * @str: Destination to write out the cipher name
 * @cipher_code: The code to convert to cipher name string
 *
 * Returns zero on success
 */
int ecryptfs_cipher_code_to_string(char *str, u8 cipher_code)
{
	int rc = 0;
	int i;

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(ecryptfs_cipher_code_str_map); i++)
		if (cipher_code == ecryptfs_cipher_code_str_map[i].cipher_code)
			strcpy(str, ecryptfs_cipher_code_str_map[i].cipher_str);
	if (str[0] == '\0') {
		ecryptfs_printk(KERN_WARNING, "Cipher code not recognized: "
				"[%d]\n", cipher_code);
		rc = -EINVAL;
	}
	return rc;
}

// 读取文件头校验文件是否为加密文件。加密文件更新inode.i_size值为原始文件长度并
// 开启加密上下文标志ECRYPTFS_I_SIZE_INITIALIZED。
// 加密文件返回值为0, 其他为非加密文件
int ecryptfs_read_and_validate_header_region(struct dentry *dentry, 
					     struct inode *inode)
{
	struct inode *lower_inode = ecryptfs_inode_to_lower(inode);
	u8 file_header[ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE];
	int rc;
	loff_t lower_i_size;

	if ((lower_i_size = i_size_read(lower_inode)) < 
		ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE) {
		return -EINVAL;
	} else {
		rc = ecryptfs_read_lower(file_header, 0, 
					 ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE,
					 inode);
		if (rc < ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE)
			return rc >= 0 ? -EINVAL : rc; // 底层文件读取的文件头
		rc = ecryptfs_validate_marker(file_header);
		if (!rc) { // 加密文件这里需要更新inode.i_size值
			ecryptfs_i_size_init(file_header, inode);
		}
	}

	return rc;
}

void
ecryptfs_write_header_metadata(char *virt,
			       struct ecryptfs_crypt_stat *crypt_stat,
			       size_t *written)
{
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = 
				ecryptfs_get_mount_crypt_stat(crypt_stat);

	u16 extent_num = (u16)(crypt_stat->extent_size / 128);
	u64 ent_id = mount_crypt_stat->enterprise_id;
	u64 user_id = mount_crypt_stat->user_id;
	u64 dev_id = mount_crypt_stat->device_id;
	virt[CSCRYPTFS_HLEN_OFFSET] = 1;
	// CSCRYPTFS_BLK_SIZE_OFFSET字段作用?
	put_unaligned_le16(extent_num, virt + CSCRYPTFS_BLK_SIZE_OFFSET);
	put_unaligned_le64(ent_id, virt + CSCRYPTFS_ENT_ID_OFFSET);
	put_unaligned_le64(user_id, virt + CSCRYPTFS_USER_ID_OFFSET);
	put_unaligned_le64(dev_id, virt + CSCRYPTFS_DEV_ID_OFFSET);
	put_unaligned_le16(1, virt + CSCRYPTFS_TLV_OFFSET);
	put_unaligned_le16(0xe8, virt + CSCRYPTFS_TLV_OFFSET + 2);
}

struct kmem_cache *ecryptfs_header_cache;

/**
 * ecryptfs_write_headers_virt
 * @page_virt: The virtual address to write the headers to
 * @max: The size of memory allocated at page_virt
 * @size: Set to the number of bytes written by this function
 * @crypt_stat: The cryptographic context
 * @ecryptfs_dentry: The eCryptfs dentry
 *
 * Returns zero on success
 */
static int ecryptfs_write_headers_virt(char *page_virt, size_t max,
				       size_t *size,
				       struct ecryptfs_crypt_stat *crypt_stat,
				       struct dentry *ecryptfs_dentry)
{
	int rc = 0;
	size_t written;

	write_ecryptfs_marker(page_virt, &written);
	ecryptfs_write_header_metadata(page_virt, crypt_stat, &written);
	return rc;
}

static int
ecryptfs_write_metadata_to_contents(struct inode *ecryptfs_inode,
				    char *virt, size_t virt_len)
{
	int rc;

	rc = ecryptfs_write_lower(ecryptfs_inode, virt,
				  0, virt_len);
	if (rc < 0)
		printk(KERN_ERR "%s: Error attempting to write header "
		       "information to lower file; rc = [%d]\n", __func__, rc);
	else
		rc = 0;
	return rc;
}

static unsigned long ecryptfs_get_zeroed_pages(gfp_t gfp_mask,
					       unsigned int order)
{
	struct page *page;

	page = alloc_pages(gfp_mask | __GFP_ZERO, order);
	if (page)
		return (unsigned long) page_address(page);
	return 0;
}

/**
 * ecryptfs_write_metadata
 * @ecryptfs_dentry: The eCryptfs dentry, which should be negative
 * @ecryptfs_inode: The newly created eCryptfs inode
 *
 * Write the file headers out.  This will likely involve a userspace
 * callout, in which the session key is encrypted with one or more
 * public keys and/or the passphrase necessary to do the encryption is
 * retrieved via a prompt.  Exactly what happens at this point should
 * be policy-dependent.
 *
 * Returns zero on success; non-zero on error
 */
int ecryptfs_write_metadata(struct dentry *ecryptfs_dentry,
			    struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	unsigned int order;
	char *virt;
	size_t virt_len;
	size_t size = 0;
	int rc = 0;
	ecryptfs_printk(KERN_DEBUG, "Write metadata to file: %s\n",
			ecryptfs_dentry->d_name.name);
	if (likely(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		if (!(crypt_stat->flags & ECRYPTFS_KEY_VALID)) {
			printk(KERN_ERR "Key is invalid; bailing out\n");
			rc = -EINVAL;
			goto out;
		}
	} else {
		printk(KERN_WARNING "%s: Encrypted flag not set\n", __func__);
		rc = -EINVAL;
		goto out;
	}
	virt_len = crypt_stat->metadata_size;
	order = get_order(virt_len);
	/* Released in this function */
	virt = (char *)ecryptfs_get_zeroed_pages(GFP_KERNEL, order);
	if (!virt) {
		printk(KERN_ERR "%s: Out of memory\n", __func__);
		rc = -ENOMEM;
		goto out;
	}
	/* Zeroed page ensures the in-header unencrypted i_size is set to 0 */
	rc = ecryptfs_write_headers_virt(virt, virt_len, &size, crypt_stat,
					 ecryptfs_dentry);
	if (unlikely(rc)) {
		printk(KERN_ERR "%s: Error whilst writing headers; rc = [%d]\n",
		       __func__, rc);
		goto out_free;
	}

	rc = ecryptfs_write_metadata_to_contents(ecryptfs_inode, virt,
						 virt_len);
	if (rc) {
		printk(KERN_ERR "%s: Error writing metadata out to lower file; "
		       "rc = [%d]\n", __func__, rc);
		goto out_free;
	}
out_free:
	free_pages((unsigned long)virt, order);
out:
	return rc;
}

#define ECRYPTFS_DONT_VALIDATE_HEADER_SIZE 0
#define ECRYPTFS_VALIDATE_HEADER_SIZE 1
static int parse_header_metadata(struct ecryptfs_crypt_stat *crypt_stat,
				 char *virt, int *bytes_read,
				 int validate_header_size)
{
	struct ecryptfs_mount_crypt_stat *mount_stat =
		ecryptfs_get_mount_crypt_stat(crypt_stat);
	u16 num_header_extents_at_front = virt[CSCRYPTFS_HLEN_OFFSET];
	ecryptfs_printk(KERN_DEBUG, "num_header_extents_at_front: %d", 
			num_header_extents_at_front);

	crypt_stat->metadata_size = (size_t)(num_header_extents_at_front * 
					ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE);
	if ((validate_header_size == ECRYPTFS_VALIDATE_HEADER_SIZE)
	    && (crypt_stat->metadata_size
		< ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE)) {
		printk(KERN_WARNING "Invalid header size: [%zd]\n",
		       crypt_stat->metadata_size);
		return -EINVAL;
	}
	crypt_stat->file_version = 1;
	//crypt_stat->extent_size = (size_t)(get_unaligned_le16(virt + 
	//				   CSCRYPTFS_BLK_SIZE_OFFSET)*128);

	mount_stat->enterprise_id = get_unaligned_le64(virt + 
						CSCRYPTFS_ENT_ID_OFFSET);
	mount_stat->user_id = get_unaligned_le64(virt + 
						CSCRYPTFS_USER_ID_OFFSET);
	mount_stat->device_id = get_unaligned_le64(virt + 
						CSCRYPTFS_DEV_ID_OFFSET);
	ecryptfs_printk(KERN_DEBUG,
		"metadata_size: %lu, extent_size:%ld, "
		"exterprise_id:%llu, user_id:%llu, device_id:%llu\n", 
			crypt_stat->metadata_size, crypt_stat->extent_size, 
			mount_stat->enterprise_id, mount_stat->user_id, 
			mount_stat->device_id);
	return 0;
}

// 初始化堆栈文件inode.i_size(只有加密文件才会调用该函数)
void ecryptfs_i_size_init(const char *page_virt, struct inode *inode)
{
	// struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_crypt_stat *crypt_stat;
	u64 file_size;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;

	// 更新inode.i_size值为底层非加密文件的长度
	file_size = get_unaligned_le64(page_virt + CSCRYPTFS_FLEN_OFFSET);
	ecryptfs_printk(KERN_DEBUG, "file original length: %lld", file_size);
	i_size_write(inode, (loff_t)file_size);
	crypt_stat->flags |= ECRYPTFS_I_SIZE_INITIALIZED;
}

/**
 * ecryptfs_read_headers_virt
 * @page_virt: The virtual address into which to read the headers
 * @crypt_stat: The cryptographic context
 * @ecryptfs_dentry: The eCryptfs dentry
 * @validate_header_size: Whether to validate the header size while reading
 *
 * Read/parse the header data. The header format is detailed in the
 * comment block for the ecryptfs_write_headers_virt() function.
 *
 * Returns zero on success
 */
static int ecryptfs_read_headers_virt(char *page_virt,
				      struct ecryptfs_crypt_stat *crypt_stat,
				      struct dentry *ecryptfs_dentry,
				      int validate_header_size)
{
	int rc = 0;
	int bytes_read;
	struct inode *inode;

	// 设置crypt_stat->extent_size与crypt_stat->metadata_size
	ecryptfs_set_default_sizes(crypt_stat);
	crypt_stat->mount_crypt_stat = &ecryptfs_superblock_to_private(
		ecryptfs_dentry->d_sb)->mount_crypt_stat;
	rc = ecryptfs_validate_marker(page_virt);
	if (rc) // 非加密文件直接返回no-zero
		goto out;
	// 校验加密文件成功,如果inode.i_size还没有更新，则更新inode.i_size值
	if (!(crypt_stat->flags & ECRYPTFS_I_SIZE_INITIALIZED))
		ecryptfs_i_size_init(page_virt, d_inode(ecryptfs_dentry));

	// 解析加密头元信息
	rc = parse_header_metadata(crypt_stat, page_virt,
				   &bytes_read, validate_header_size);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error reading header "
				"metadata; rc = [%d]\n", rc);
		goto out;	
	}
	// 加密文件初始化对称加密对象
	inode = &container_of(crypt_stat, 
			struct ecryptfs_inode_info, crypt_stat)->vfs_inode;

	ecryptfs_new_file_context(inode);
out:
	return rc;
}

/**
 * ecryptfs_read_metadata
 *
 * Common entry point for reading file metadata. From here, we could
 * retrieve the header information from the header region of the file,
 * the xattr region of the file, or some other repository that is
 * stored separately from the file itself. The current implementation
 * supports retrieving the metadata information from the file contents
 * and from the xattr region.
 *
 * Returns zero if valid headers found and parsed; non-zero otherwise
 */
int ecryptfs_read_metadata(struct dentry *ecryptfs_dentry)
{
	int rc;
	char *page_virt;
	struct inode *ecryptfs_inode = d_inode(ecryptfs_dentry);
	struct ecryptfs_crypt_stat *crypt_stat =
	    &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(
			ecryptfs_dentry->d_sb)->mount_crypt_stat;

	ecryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	/* Read the first page from the underlying file */
	page_virt = kmem_cache_alloc(ecryptfs_header_cache, GFP_USER);
	if (!page_virt) {
		rc = -ENOMEM;
		goto out;
	}
	// 读取exten_size字节数据(extent_size default=4096)
	rc = ecryptfs_read_lower(page_virt, 0, crypt_stat->extent_size,
				 ecryptfs_inode);
	if (rc >= 0)
		// 解析文件头并更新crypt_stat对象的成员值
		rc = ecryptfs_read_headers_virt(page_virt, crypt_stat,
						ecryptfs_dentry,
						ECRYPTFS_VALIDATE_HEADER_SIZE);
out:
	if (page_virt) {
		memset(page_virt, 0, PAGE_SIZE);
		kmem_cache_free(ecryptfs_header_cache, page_virt);
	}
	return rc;
}

static int ecryptfs_copy_filename(char **copied_name, size_t *copied_name_size,
				  const char *name, size_t name_size)
{
	int rc = 0;

	(*copied_name) = kmalloc((name_size + 1), GFP_KERNEL);
	if (!(*copied_name)) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*copied_name), (void *)name, name_size);
	(*copied_name)[(name_size)] = '\0';	/* Only for convenience
						 * in printing out the
						 * string in debug
						 * messages */
	(*copied_name_size) = name_size;
out:
	return rc;
}

/**
 * ecryptfs_process_key_cipher - Perform key cipher initialization.
 * @key_tfm: Crypto context for key material, set by this function
 * @cipher_name: Name of the cipher
 * @key_size: Size of the key in bytes
 *
 * Returns zero on success. Any crypto_tfm structs allocated here
 * should be released by other functions, such as on a superblock put
 * event, regardless of whether this function succeeds for fails.
 */
static int
ecryptfs_process_key_cipher(struct crypto_skcipher **key_tfm,
			    char *cipher_name, size_t *key_size)
{
	char *full_alg_name = NULL;
	int rc;

	*key_tfm = NULL;
	if (*key_size > ECRYPTFS_MAX_KEY_BYTES) {
		rc = -EINVAL;
		printk(KERN_ERR "Requested key size is [%zd] bytes; maximum "
		      "allowable is [%d]\n", *key_size, ECRYPTFS_MAX_KEY_BYTES);
		goto out;
	}
	rc = ecryptfs_crypto_api_algify_cipher_name(&full_alg_name, cipher_name,
						    "ecb");
	if (rc)
		goto out;
	// full_alg_name 格式为%s(%s)字符串, 设置加解密模式为异步
	*key_tfm = crypto_alloc_skcipher(full_alg_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(*key_tfm)) {
		rc = PTR_ERR(*key_tfm);
		printk(KERN_ERR "Unable to allocate crypto cipher with name "
		       "[%s]; rc = [%d]\n", full_alg_name, rc);
		goto out;
	}
	crypto_skcipher_set_flags(*key_tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	if (*key_size == 0)
		*key_size = crypto_skcipher_default_keysize(*key_tfm);
	// 设置key与key_size
	rc = crypto_skcipher_setkey(*key_tfm, CSCRYPTFS_TEST_FEK, *key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to set key of size [%zd] for "
		       "cipher [%s]; rc = [%d]\n", *key_size, full_alg_name,
		       rc);
		rc = -EINVAL;
		goto out;
	}
out:
	kfree(full_alg_name);
	return rc;
}

int
ecryptfs_create_key_tfm(struct ecryptfs_key_tfm **key_tfm, char *cipher_name,
			 size_t key_size)
{
	struct ecryptfs_key_tfm *tmp_tfm;
	int rc = 0;

	tmp_tfm = kmalloc(sizeof(*tmp_tfm), GFP_KERNEL);
	if (key_tfm)
		(*key_tfm) = tmp_tfm;
	if (!tmp_tfm) {
		rc = -ENOMEM;
		goto out;
	}
	mutex_init(&tmp_tfm->key_tfm_mutex);
	strncpy(tmp_tfm->cipher_name, cipher_name,
		ECRYPTFS_MAX_CIPHER_NAME_SIZE);
	tmp_tfm->cipher_name[ECRYPTFS_MAX_CIPHER_NAME_SIZE] = '\0';
	tmp_tfm->key_size = key_size;
	rc = ecryptfs_process_key_cipher(&tmp_tfm->key_tfm,
					 tmp_tfm->cipher_name,
					 &tmp_tfm->key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to initialize key TFM "
		       "cipher with name = [%s]; rc = [%d]\n",
		       tmp_tfm->cipher_name, rc);
		kfree(tmp_tfm);
		if (key_tfm)
			(*key_tfm) = NULL;
		goto out;
	}
out:
	return rc;
}

void destroy_cipher_key_tfm(struct ecryptfs_key_tfm *cipher_key_tfm)
{
	if (cipher_key_tfm != NULL) {
		crypto_free_skcipher(cipher_key_tfm->key_tfm);
		kfree(cipher_key_tfm);
		ecryptfs_printk(KERN_DEBUG, "Destroy cipher_key_tfm succsess\n");
	}
}

/**
 * ecryptfs_decode_and_decrypt_filename - converts the encoded cipher text name to decoded plaintext
 * @plaintext_name: The plaintext name
 * @plaintext_name_size: The plaintext name size
 * @ecryptfs_dir_dentry: eCryptfs directory dentry
 * @name: The filename in cipher text
 * @name_size: The cipher text name size
 *
 * Decrypts and decodes the filename.
 *
 * Returns zero on error; non-zero otherwise
 */
int ecryptfs_decode_and_decrypt_filename(char **plaintext_name,
					 size_t *plaintext_name_size,
					 struct super_block *sb,
					 const char *name, size_t name_size)
{
	int rc = 0;

	rc = ecryptfs_copy_filename(plaintext_name,
				    plaintext_name_size,
				    name, name_size);
	return rc;
}

#define ENC_NAME_MAX_BLOCKLEN_8_OR_16	143

int ecryptfs_set_f_namelen(long *namelen, long lower_namelen,
			   struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	(*namelen) = lower_namelen;
	return 0;
}

// we define function below for our buesenese
struct qstr *dup_enterprise_dentry_name_off_csx(struct qstr *dname) 
{
	struct qstr *dn = NULL;
	char *name = NULL;
	size_t len;

	len = dname->len -CSCRYPTFS_FNAME_SUFFIX_LEN;	
	if (strcmp(dname->name + len, ".csx") != 0) {
		return NULL;
	}
	dn = kzalloc(sizeof(*dn), GFP_KERNEL);
	name = kzalloc(len + 1, GFP_KERNEL);
 	dn->len = len;
	strncpy(name, dname->name, dn->len);
	dn->name = name;
	return dn;
}

void free_enterprise_dentry_name(struct qstr *dname)
{
	if (dname) {
		if (dname->name) kfree(dname->name);
		kfree(dname);
	}
	return;
}

//dname 这里的name已经去除'.csx'后缀
int app_behavior_credible(u64 enterprise_id, struct qstr *dname, 
			  struct ecryptfs_mount_crypt_stat *mount_crypt_stat) 
{
	char *ext = strrchr(dname->name, '.');
	if (!ext) return 0;		//file extension name
	ext++;	//skip '.'
	mutex_lock(&mount_crypt_stat->mux);
	if ((mount_crypt_stat->flags & CSCRYPTFS_USER_LOGIN) 
			&& enterprise_id == mount_crypt_stat->enterprise_id) {	//登录情况下才允许解密
		for ( int i = 0; i < mount_crypt_stat->entrys_num; i++) {
			if (!strncmp(ext, mount_crypt_stat->credit_entrys[i].ext, FILE_MAX_EXT_LEN - 1)) {
				for( int j = 0; j < EXT_MAX_CREDIT_NUM; ++j) {
					if (!strncmp(current->comm, mount_crypt_stat->credit_entrys[i].comms[j], TASK_COMM_LEN - 1)) {
						mutex_unlock(&mount_crypt_stat->mux);
						return 1;
					}
				}
			}
		}
	}
	mutex_unlock(&mount_crypt_stat->mux);
	return 0;
}

int file_ext_need_attention(struct qstr *dname, 
			    struct ecryptfs_mount_crypt_stat *mount_crypt_stat) 
{
	char *ext = strrchr(dname->name, '.');
	if (!ext) return 0;		//file extension name

	if (filename_suffixed_with_csx(dname)) return 1; 
	ext++;	//skip '.'
	mutex_lock(&mount_crypt_stat->mux);
	for ( int i = 0; i < mount_crypt_stat->entrys_num; i++) {
		if (!strncmp(ext, mount_crypt_stat->credit_entrys[i].ext, FILE_MAX_EXT_LEN - 1)){
			mutex_unlock(&mount_crypt_stat->mux);
			return 1;
		}
	}
	mutex_unlock(&mount_crypt_stat->mux);
	return 0;
}

//报告上层应用待处理的企业文件
int report_undo_enterprise_file(int suspected, u64 last_modify, const char *fpath) 
{
	char *buff = kmem_cache_alloc(ecryptfs_path_cache, GFP_USER);
	if (buff) {
		int len = snprintf(buff, PATH_MAX, "%d|%llu|%s|%s\n", suspected, last_modify, current->comm, fpath);
		send_netlink_msg(buff, len + 1, ENT_FILE_REPORT_PORT, 1, CSFSNETLINK_C_UNDO_ENT_FILE, CSFSNETLINK_A_UNDO_ENT_FILE);
		ecryptfs_printk(KERN_DEBUG, "report undo enterprise file:%s\n", buff);
		memset(buff, 0, PATH_MAX);
		kmem_cache_free(ecryptfs_path_cache, buff);
	}
	return 0;
}

char *ecryptfs_dentry_fullpath(const char *mount_point, struct dentry *dentry, 
			       char *buf, int buflen)
{
	char *pbuf = kmem_cache_alloc(ecryptfs_path_cache, GFP_USER);
	if (pbuf) {
		char *fpath = dentry_path_raw(dentry, pbuf, PATH_MAX);
		snprintf(buf, buflen, "%s%s", mount_point, fpath);
		memset(pbuf, 0, PATH_MAX);
		kmem_cache_free(ecryptfs_path_cache, pbuf);
		return buf;
	}
	return NULL;
}

int report_enterprise_file_event(const char *tag, u64 last_modify, 
				 const char *fpath)
{
	char *buff = kmem_cache_alloc(ecryptfs_path_cache, GFP_USER);
	if (buff) {
		int len = snprintf(buff, PATH_MAX, "%s|%llu|%s|%s\n", tag, last_modify, current->comm, fpath);
		send_netlink_msg(buff, len + 1, ENT_FILE_REPORT_PORT, 1, CSFSNETLINK_C_REPORT_ENT_FILE_EVENT, CSFSNETLINK_A_ENT_FILE_EVENT);
		ecryptfs_printk(KERN_DEBUG, "report undo enterprise file:%s\n", buff);
		memset(buff, 0, PATH_MAX);
		kmem_cache_free(ecryptfs_path_cache, buff);
	}
	return 0;
}

int report_enterprise_file_rename(u64 last_modify, const char *old_fpath, 
				  const char *new_fpath)
{
	char *buff = kmem_cache_alloc(ecryptfs_path_cache, GFP_USER);
	if (buff) {
		int len = snprintf(buff, PATH_MAX, "%s|%llu|%s|%s|%s\n", CSCRYPTFS_EVENT_RENAME, last_modify, current->comm, old_fpath, new_fpath);
		send_netlink_msg(buff, len + 1, ENT_FILE_REPORT_PORT, 1, CSFSNETLINK_C_REPORT_ENT_FILE_EVENT, CSFSNETLINK_A_ENT_FILE_EVENT);
		ecryptfs_printk(KERN_DEBUG, "report undo enterprise file:%s\n", buff);
		memset(buff, 0, PATH_MAX);
		kmem_cache_free(ecryptfs_path_cache, buff);
	}
	return 0;
}
