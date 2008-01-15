/* trustdb.c - High level interface for ownertrust handling
 *        Copyright (C) 2001, 2002, 2003, 2007 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * The OpenCDK library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>

#include "opencdk.h"
#include "main.h"

/* This code used the internal details of the GPG
   trust DB. There is no public interface available
   and thus we cannot rely on it. It might change at any time. */

int
cdk_trustdb_get_ownertrust (cdk_stream_t inp, cdk_pubkey_t pk,
			    int *r_val, int *r_flags)
{
  *r_val = CDK_TRUST_UNKNOWN;
  *r_flags = 0;
  return CDK_Not_Implemented;
}

int
cdk_trustdb_get_validity (cdk_stream_t inp, cdk_pkt_userid_t id, int *r_val)
{
  *r_val = CDK_TRUST_UNKNOWN;
  return CDK_Not_Implemented;
}
