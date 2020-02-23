/**
 * eCryptfs: Linux filesystem encryption layer
 * In-kernel key management code.  Includes functions to parse and
 * write authentication token-related packets with the underlying
 * file.
 *
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *              Trevor S. Highland <trevor.highland@gmail.com>
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
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "ecryptfs_kernel.h"

// 更新企业状态
const char *cscryptfs_db_path =  "/opt/test/db/fs.dat";
struct ecryptfs_enterprise_stat enterprise_stat;

int encryptfs_enterprise_init(void)
{
    memset(&enterprise_stat, 0, sizeof(enterprise_stat));

    struct file *fp = filp_open(cscryptfs_db_path, O_RDONLY, 0);
    if (!IS_ERR(fp)){
        mm_segment_t fs = get_fs();
        set_fs(KERNEL_DS);
        loff_t pos=0;
        vfs_read(fp, (char *)&enterprise_stat, sizeof(enterprise_stat), &pos);
        set_fs(fs);
        filp_close(fp, NULL);
	}
    return 0;
}

int encryptfs_enterprise_save(void)
{
    struct file *fp = filp_open(cscryptfs_db_path, O_CREAT|O_WRONLY, 0660);
	if (!IS_ERR(fp)) {
        mm_segment_t fs = get_fs();
	    set_fs(KERNEL_DS);
        loff_t pos=0;
		vfs_write(fp, (const char *)&enterprise_stat, sizeof(enterprise_stat), &pos);
        set_fs(fs);
        filp_close(fp, NULL);
	}
    return 0;
}

void encryptfs_enterprise_parse(struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
    if (enterprise_stat.login) {
        mount_crypt_stat->flags |= CSCRYPTFS_USER_LOGIN;
        memcpy(CSCRYPTFS_TEST_FEK, enterprise_stat.key, ECRYPTFS_DEFAULT_KEY_BYTES);
        mount_crypt_stat->enterprise_id = enterprise_stat.enterprise_id;
	    mount_crypt_stat->user_id =	enterprise_stat.user_id;				
        mount_crypt_stat->device_id = enterprise_stat.device_id;
	    mount_crypt_stat->entrys_num = enterprise_stat.entrys_num;
        memcpy(&mount_crypt_stat->credit_entrys, enterprise_stat.credit_entrys, sizeof(enterprise_stat.credit_entrys));
    } else {
        mount_crypt_stat->flags &= ~CSCRYPTFS_USER_LOGIN;
    }
    return;
}
