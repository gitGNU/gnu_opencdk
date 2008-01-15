/* write-compress.c
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

#ifdef HAVE_LIBZ
#include <stdio.h>
#include <zlib.h>
#include <string.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"

#define BUFFERSIZE 4096


/* Context for the compression. */
struct compress_writer_s
{
  z_stream *zs;
  unsigned char outbuf[BUFFERSIZE];
  int head_written;
  int zlib_error;
  int algo;
};


static int
compress_data (compress_writer_t ctx, int flush, 
	       unsigned char *inbuf, size_t insize, cdk_writer_t out)
{
  z_stream *zs = ctx->zs;
  unsigned char buf[BUFFERSIZE];
  int nbytes, zrc;
  size_t n;
  
  zs->next_in = inbuf;
  zs->avail_in = insize;  
  n = 0;
  
  do 
    {
      zs->next_out = buf;
      zs->avail_out = BUFFERSIZE;
      
      zrc = deflate (zs, flush);
      if (zrc == Z_STREAM_END && flush == Z_FINISH)
	;
      else if (zrc != Z_OK)
	{
	  ctx->zlib_error = zrc;
	  break;
	}      
      nbytes = BUFFERSIZE - zs->avail_out;
      n += _cdk_writer_write_next (out, buf, nbytes);
    }
  while (zs->avail_out == 0 || (flush == Z_FINISH && zrc != Z_STREAM_END));
  return n;
}


/* It is possible that the function return 0 because not each
   input results in a compressed output block. It depends on
   the blocksize. */
static int
compress_write (cdk_writer_t w, void *_ctx, const void *buf, size_t buflen)
{
  compress_writer_t ctx = (compress_writer_t)_ctx;
  size_t off, nwrite;
  int n = 0;
  
  /* Do not continue if an error has occurred. */
  if (ctx->zlib_error)
    {
      _cdk_log_debug ("compress_write: zlib error; abort\n");
      return -1;
    }  
    
  /* Write the packet head for the compressed packet.
     Use an infinite length header to avoid the partial mode. */
  if (!ctx->head_written)
    {
      unsigned char pkt[2];

      pkt[0] = 0x80|(8 << 2)|3;
      pkt[1] = 1;
      _cdk_writer_write_next (w, pkt, 2);
      ctx->head_written = 1;
    }
  
  off = 0;
  while (buflen > 0)
    {
      nwrite = buflen > BUFFERSIZE? BUFFERSIZE : buflen;
      _cdk_log_debug ("compress_write: %d bytes of %d\n", nwrite, buflen);
      memcpy (ctx->outbuf, (unsigned char*)buf + off, nwrite);
      n = compress_data (ctx, Z_NO_FLUSH, ctx->outbuf, nwrite, w);
      buflen -= nwrite;
      off += nwrite;
    }  
  
  return n;
}


static int
compress_flush (cdk_writer_t w)
{
  compress_writer_t ctx = (compress_writer_t)cdk_writer_get_opaque (w);
  
  _cdk_log_debug ("compress_flush : done head=%d\n", ctx->head_written);
  if (!ctx->head_written)
    return 0;
  
  compress_data (ctx, Z_FINISH, ctx->outbuf, 0, w);
  if (ctx->zlib_error)
    return -1;
  return 0;
}


static int
compress_release (void *ctx)
{
  compress_writer_t zip = (compress_writer_t)ctx;
  
  _cdk_log_debug ("compress_close: algo %d\n", zip->algo);
  deflateEnd (zip->zs);
  cdk_free (zip->zs);
  cdk_free (zip);
  
  return 0;
}


static int
compress_init (void **r_ctx)
{
  compress_writer_t c;
  
  c = cdk_calloc (1, sizeof *c);
  if (!c)
    return CDK_Out_Of_Core;
  
  c->algo = 1;
  c->zs = cdk_calloc (1, sizeof *c->zs);
  if (!c->zs)
    {
      cdk_free (c);
      return CDK_Out_Of_Core;
    }
  
  *r_ctx = c;
  return 0;
}


cdk_error_t
compress_writer_new (compress_writer_t *r_zip, int algo)
{
  void *zip;
  cdk_error_t err;
  
  err = compress_init (&zip);
  if (err)
    return err;
  
  *r_zip = (compress_writer_t)zip;
  err = compress_writer_set_algorithm (*r_zip, algo);
  return err;
}


cdk_error_t
compress_writer_set_algorithm (compress_writer_t zip, int algorithm)
{
  int zrc;
  
  zip->algo = algorithm;
  
  if (algorithm == 1)
    zrc = deflateInit2 (zip->zs, 6, Z_DEFLATED, 
			-13, 8, Z_DEFAULT_STRATEGY);
  else
    zrc = inflateInit (zip->zs);
  if (zrc != Z_OK)
    return CDK_Zlib_Error;
  return 0;
}


cdk_error_t
cdk_writer_compress_new (cdk_writer_t *r_wr, cdk_writer_t next,
			 compress_writer_t zip)
{
  return cdk_writer_new (r_wr, next, &compress_writer, zip);
}


struct cdk_writer_cbs_s compress_writer = 
{compress_write, compress_flush, compress_release, compress_init};
#endif
