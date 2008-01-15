/* read-digest.c - Digest reader
 *       Copyright (C) 2007 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"


/* Digest reader context. */
struct digest_reader_s
{
  int gcry_error;
  int algo;
  gcry_md_hd_t md;
};


/* Update the message digest with the given buffer contents. */
static int
digest_read (cdk_reader_t rd, void *ctx, void *buf, size_t buflen)
{
  digest_reader_t dr = (digest_reader_t)ctx;
  int n;
  
  if (dr->gcry_error)
    return -1;
  
  if (!dr->md)
    {      
      if (gcry_md_open (&dr->md, dr->algo, 0))
	{
	  _cdk_log_debug ("digest_read: error while md open\n");
	  dr->gcry_error = 1;
	  return -1;
	}      
      _cdk_log_debug ("digest_read: open\n");
    }  
  
  n = _cdk_reader_read_next (rd, buf, buflen);
  gcry_md_write (dr->md, buf, n);
  return n;
}


/* Release digest context. */
static int
digest_release (void *ctx)
{
  digest_reader_t md = (digest_reader_t)ctx;
  
  _cdk_log_debug ("digest_release: close\n");
  gcry_md_close (md->md);
  md->algo = 0;
  cdk_free (md);
  
  return 0;
}


/* Allocate new digest context. */
static int
digest_init (void **r_ctx)
{
  digest_reader_t d;
  
  d = cdk_calloc (1, sizeof *d);
  if (!d)
    return CDK_Out_Of_Core;
  d->algo = GCRY_MD_SHA1;
  *r_ctx = d;
  return 0;
}


/* Allocate a new digest reader with the given algorithm. */
cdk_error_t
digest_reader_new (digest_reader_t *r_md, int algo)
{
  void *md;
  cdk_error_t err;
  
  *r_md = NULL;
  err = digest_init (&md);
  if (err)
    return err;
  
  err = digest_reader_set_algorithm ((digest_reader_t)md, algo);
  if (err)
    {
      digest_release (md);
      return err;
    }
  
  *r_md = (digest_reader_t)md;
  return 0;
}


/**
 * cdk_reader_digest_new:
 * @r_rd: the new reader object
 * @next: the next reader object
 * @md: the digest reader context
 * 
 * Allocate a new digest reader.
 **/
cdk_error_t
cdk_reader_digest_new (cdk_reader_t *r_rd, cdk_reader_t next,
		       digest_reader_t md)
{
  return cdk_reader_new (r_rd, next, &digest_reader, md);
}


/* Set the algorithm for the given digest reader. */
cdk_error_t
digest_reader_set_algorithm (digest_reader_t d, int algorithm)
{
  d->algo = algorithm;
  return 0;
}


/* Return a allocated copy of the digest. Call must free the handle. */
cdk_error_t
digest_reader_get_handle (digest_reader_t d, gcry_md_hd_t *r_md)
{
  if (gcry_md_copy (r_md, d->md))
    return CDK_Inv_Value;
  return 0;
}


/* Module handle for the digest routines. */
struct cdk_reader_cbs_s digest_reader =
{digest_read, digest_release, digest_init};
