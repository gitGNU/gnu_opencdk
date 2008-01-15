/* write-buffer.c
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
#include <malloc.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"

#define BUFFERSIZE 1024

struct buffer_writer_s
{
  unsigned char *buffer;
  size_t bufsize;
  size_t off;
};
  

static int
buffer_init (void **r_ctx)
{
  buffer_writer_t buf;
  
  buf = cdk_calloc (1, sizeof *buf);
  if (!buf)
    return CDK_Out_Of_Core;
  buf->buffer = cdk_calloc (1, BUFFERSIZE);
  buf->bufsize = BUFFERSIZE;
  *r_ctx = buf;
  
  return 0;
}


static int
buffer_release (void *ctx)
{
  buffer_writer_t buf = (buffer_writer_t)ctx;
  
  _cdk_log_debug ("buffer_release: size %d used %d\n",
		  buf->bufsize, buf->off);
  cdk_free (buf->buffer);
  cdk_free (buf);
  return 0;
}


static int
buffer_flush (cdk_writer_t wr)
{
  buffer_writer_t buf = (buffer_writer_t)cdk_writer_get_opaque (wr);
  
  _cdk_log_debug ("buffer_flush: done\n");
  buf->off = 0;
  
  return 0;
}


static int
buffer_write (cdk_writer_t wr, void *ctx, const void *buf, size_t buflen)
{
  buffer_writer_t b = (buffer_writer_t)ctx;
  
  if (buflen > (b->bufsize - b->off))
    {
      unsigned char *old = b->buffer;
      size_t oldlen = b->bufsize;
      
      /* Extra room to avoid too much allocation calls. */
      b->bufsize += BUFFERSIZE;
      /* Increase the buffer to make room for the input data. */
      b->bufsize += buflen;
      b->buffer = cdk_calloc (1, b->bufsize);
      memcpy (b->buffer, old, oldlen);
      cdk_free (old);
      _cdk_log_debug ("buffer_write: enlarge from %d to %d\n",
		      oldlen, b->bufsize);
    }  
  memcpy (b->buffer + b->off, buf, buflen);
  b->off += buflen;
  
  return buflen;
}


cdk_error_t
buffer_writer_get_data (buffer_writer_t buf, 
			unsigned char **r_data, size_t *r_data_len)
{
  unsigned char *data;
  
  if (!buf || !r_data || !r_data_len)
    return CDK_Inv_Value;
  
  *r_data_len = buf->off;
  data = cdk_calloc (1, buf->off);
  if (!data)
    return CDK_Out_Of_Core;
  memcpy (data, buf->buffer, buf->off);
  *r_data = data;
  
  return 0;
}


cdk_error_t
buffer_writer_new (buffer_writer_t *r_buf)
{
  void *ctx;
  int err;
  
  err = buffer_init (&ctx);
  if (err)
    return err;
  
  *r_buf = (buffer_writer_t)ctx;
  return 0;
}


cdk_error_t
cdk_writer_buffer_new (cdk_writer_t *r_wr, buffer_writer_t buf)
{
  return cdk_writer_new (r_wr, NULL, &buffer_writer, buf);
}


struct cdk_writer_cbs_s buffer_writer =
{buffer_write, buffer_flush, buffer_release, buffer_init};
