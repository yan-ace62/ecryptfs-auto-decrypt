/**
 * eCryptfs: Linux filesystem encryption layer
 * This is where eCryptfs coordinates the symmetric encryption and
 * decryption of the file data as it passes between the lower
 * encrypted file and the upper decrypted file.
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
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

#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/page-flags.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <asm/unaligned.h>
#include "ecryptfs_kernel.h"

/**
 * ecryptfs_get_locked_page
 *
 * Get one page from cache or lower f/s, return error otherwise.
 *
 * Returns locked and up-to-date page (if ok), with increased refcnt.
 */
struct page *ecryptfs_get_locked_page(struct inode *inode, loff_t index)
{
	struct page *page = read_mapping_page(inode->i_mapping, index, NULL);
	if (!IS_ERR(page))
		lock_page(page);
	return page;
}

/**
 * ecryptfs_writepage
 * @page: Page that is locked before this call is made
 *
 * Returns zero on success; non-zero otherwise
 *
 * This is where we encrypt the data and pass the encrypted data to
 * the lower filesystem.
 */
// TODO BUG 如果对非加密文件进行原文回写修改，就会出发系统重启的BUG(主要出现在mmap操作过程)
static int ecryptfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int rc;

	// 加密页数据并将其写入底层文件
	rc = ecryptfs_encrypt_page(page);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error encrypting "
				"page (upper index [0x%.16lx])\n", page->index);
		ClearPageUptodate(page);
		goto out;
	}
	SetPageUptodate(page);
out:
	unlock_page(page);
	return rc;
}

/**
 * ecryptfs_readpage
 * @file: An eCryptfs file
 * @page: Page from eCryptfs inode mapping into which to stick the read data
 *
 * Read in a page, decrypting if necessary.
 *
 * Returns zero on success; non-zero on error.
 */
static int ecryptfs_readpage(struct file *file, struct page *page)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(page->mapping->host)->crypt_stat;
	int rc = 0;

	// crypt_stat==NULL出现在什么情况下？
	if (!crypt_stat || !(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		// 从底层文件系统读取完整的一页数据
		rc = ecryptfs_read_lower_page_segment(page, page->index, 0,
						      PAGE_SIZE,
						      page->mapping->host);
	} else { // 加密文件读取
		rc = ecryptfs_decrypt_page(page); // 解密缓存页数据
		if (rc) {
			ecryptfs_printk(KERN_ERR, "Error decrypting page; "
					"rc = [%d]\n", rc);
			goto out;
		}
	}
out:
	if (rc) // 如果读取数据失败
		ClearPageUptodate(page);
	else
		SetPageUptodate(page);
	ecryptfs_printk(KERN_DEBUG, "Unlocking page with index = [0x%.16lx]\n",
			page->index);
	unlock_page(page);
	return rc;
}

/**
 * Called with lower inode mutex held.
 */
static int fill_zeros_to_end_of_page(struct page *page, unsigned int to)
{
	struct inode *inode = page->mapping->host;
	int end_byte_in_page;

	if ((i_size_read(inode) / PAGE_SIZE) != page->index) // 如果page不是文件最后一页，那么直接返回函数
		goto out;
	end_byte_in_page = i_size_read(inode) % PAGE_SIZE;
	if (to > end_byte_in_page)
		end_byte_in_page = to;
	zero_user_segment(page, end_byte_in_page, PAGE_SIZE);
out:
	return 0;
}

/**
 * ecryptfs_write_begin
 * @file: The eCryptfs file
 * @mapping: The eCryptfs object
 * @pos: The file offset at which to start writing
 * @len: Length of the write
 * @flags: Various flags
 * @pagep: Pointer to return the page
 * @fsdata: Pointer to return fs data (unused)
 *
 * This function must zero any hole we create
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_write_begin(struct file *file,
				struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_SHIFT; // 计算出页索引
	struct page *page;
	loff_t prev_page_end_size;
	int rc = 0;

	// Find or create a page at the given pagecache position. Return the locked page. 
	// This function is specifically for buffered writes.
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	prev_page_end_size = ((loff_t)index << PAGE_SHIFT);
	// PG_uptodate tells whether the page's contents is valid.
	// 如果数据不是有效，进行下面处理
	if (!PageUptodate(page)) {
		struct ecryptfs_crypt_stat *crypt_stat =
			&ecryptfs_inode_to_private(mapping->host)->crypt_stat;

		if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) { // 非加密文件
			rc = ecryptfs_read_lower_page_segment(
				page, index, 0, PAGE_SIZE, mapping->host);
			if (rc) {
				printk(KERN_ERR "%s: Error attempting to read "
				       "lower page segment; rc = [%d]\n",
				       __func__, rc);
				ClearPageUptodate(page);
				goto out;
			} else
				// Set PG_uptodate flags
				SetPageUptodate(page);
		} else { // 加密文件
			if (prev_page_end_size
			    >= i_size_read(page->mapping->host)) {
				zero_user(page, 0, PAGE_SIZE);
				SetPageUptodate(page);
			} else if (len < PAGE_SIZE) {
				rc = ecryptfs_decrypt_page(page);
				if (rc) {
					printk(KERN_ERR "%s: Error decrypting "
					       "page at index [%ld]; "
					       "rc = [%d]\n",
					       __func__, page->index, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			}
		}
	}
	/* If creating a page or more of holes, zero them out via truncate.
	 * Note, this will increase i_size. */
	if (index != 0) {
		if (prev_page_end_size > i_size_read(page->mapping->host)) {
			rc = ecryptfs_truncate(file->f_path.dentry,
					       prev_page_end_size);
			if (rc) {
				printk(KERN_ERR "%s: Error on attempt to "
				       "truncate to (higher) offset [%lld];"
				       " rc = [%d]\n", __func__,
				       prev_page_end_size, rc);
				goto out;
			}
		}
	}
	/* Writing to a new page, and creating a small hole from start
	 * of page?  Zero it out. */
	if ((i_size_read(mapping->host) == prev_page_end_size)
	    && (pos != 0))
		zero_user(page, 0, PAGE_SIZE);
out:
	if (unlikely(rc)) {
		unlock_page(page);
		put_page(page);
		*pagep = NULL;
	}
	return rc;
}

/**
 * ecryptfs_write_inode_size_to_header
 *
 * Writes the lower file size to the first 8 bytes of the header.
 *
 * Returns zero on success; non-zero on error.
 */
static int ecryptfs_write_inode_size_to_header(struct inode *ecryptfs_inode)
{
	char *file_size_virt;
	int rc;

	file_size_virt = kmalloc(sizeof(u64), GFP_KERNEL);
	if (!file_size_virt) {
		rc = -ENOMEM;
		goto out;
	}
	put_unaligned_le64(i_size_read(ecryptfs_inode), file_size_virt);
	rc = ecryptfs_write_lower(ecryptfs_inode, file_size_virt, 
				  CSCRYPTFS_FLEN_OFFSET, sizeof(u64));
	kfree(file_size_virt);
	if (rc < 0)
		printk(KERN_ERR "%s: Error writing file size to header; "
		       "rc = [%d]\n", __func__, rc);
	else
		rc = 0;
out:
	return rc;
}

int ecryptfs_write_inode_size_to_metadata(struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat;

	crypt_stat = &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));
	return ecryptfs_write_inode_size_to_header(ecryptfs_inode);
}

/**
 * ecryptfs_write_end
 * @file: The eCryptfs file object
 * @mapping: The eCryptfs object
 * @pos: The file position
 * @len: The length of the data (unused)
 * @copied: The amount of data copied
 * @page: The eCryptfs page
 * @fsdata: The fsdata (unused)
 */
static int ecryptfs_write_end(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + copied;
	struct inode *ecryptfs_inode = mapping->host;
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	int rc;

	ecryptfs_printk(KERN_DEBUG, "Calling fill_zeros_to_end_of_page"
			"(page w/ index = [0x%.16lx], to = [%d])\n", index, to);
	if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) { // 非加密文件处理流程
		rc = ecryptfs_write_lower_page_segment(ecryptfs_inode, page, 0,
						       to);
		if (!rc) {
			rc = copied;
			fsstack_copy_inode_size(ecryptfs_inode,
				ecryptfs_inode_to_lower(ecryptfs_inode));
		}
		goto out;
	}
	if (!PageUptodate(page)) {
		if (copied < PAGE_SIZE) {
			rc = 0;
			goto out;
		}
		SetPageUptodate(page);
	}
	/* Fills in zeros if 'to' goes beyond inode size */
	rc = fill_zeros_to_end_of_page(page, to);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to fill "
			"zeros in page with index = [0x%.16lx]\n", index);
		goto out;
	}
	// 加密页数据并将其写入底层文件
	rc = ecryptfs_encrypt_page(page);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error encrypting page (upper "
				"index [0x%.16lx])\n", index);
		goto out;
	}
	if (pos + copied > i_size_read(ecryptfs_inode)) {
		i_size_write(ecryptfs_inode, pos + copied);
		ecryptfs_printk(KERN_DEBUG, "Expanded file size to "
			"[0x%.16llx]\n",
			(unsigned long long)i_size_read(ecryptfs_inode));
	}
	rc = ecryptfs_write_inode_size_to_metadata(ecryptfs_inode);
	if (rc)
		printk(KERN_ERR "Error writing inode size to metadata; "
		       "rc = [%d]\n", rc);
	else
		rc = copied;
out:
	unlock_page(page);
	put_page(page);
	return rc;
}

static sector_t ecryptfs_bmap(struct address_space *mapping, sector_t block)
{
	int rc = 0;
	struct inode *inode;
	struct inode *lower_inode;

	inode = (struct inode *)mapping->host;
	lower_inode = ecryptfs_inode_to_lower(inode);
	if (lower_inode->i_mapping->a_ops->bmap)
		rc = lower_inode->i_mapping->a_ops->bmap(lower_inode->i_mapping,
							 block);
	return rc;
}

const struct address_space_operations ecryptfs_aops = {
	.writepage = ecryptfs_writepage,
	.readpage = ecryptfs_readpage,
	.write_begin = ecryptfs_write_begin,
	.write_end = ecryptfs_write_end,
	.bmap = ecryptfs_bmap,
};
