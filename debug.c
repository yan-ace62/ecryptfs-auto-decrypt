/**
 * eCryptfs: Linux filesystem encryption layer
 * Functions only useful for debugging.
 *
 * Copyright (C) 2006 International Business Machines Corp.
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

#include "ecryptfs_kernel.h"
#include <linux/kernel.h>
#include <linux/slab.h>

/**
 * ecryptfs_dump_hex - debug hex printer
 * @data: string of bytes to be printed
 * @bytes: number of bytes to print
 *
 * Dump hexadecimal representation of char array
 */
void ecryptfs_dump_hex(char *data, int bytes)
{
	int i = 0;

	char *hex_str = kmalloc(2 * bytes + 1, GFP_KERNEL);

        while (i < bytes) {
                sprintf(hex_str + 2*i, "%.2x", (unsigned char)data[i]);
                i++;
        }
        *(hex_str+2*i) = '\0';
	if (ecryptfs_verbosity > 0)
        	ecryptfs_printk(KERN_DEBUG, "0x%s", hex_str);
        kfree(hex_str);

        return;
}