/* write-buffered.c
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
#include <stdio.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"


/* Writer with the ability to buffer data. */
struct buffered_writer_s
{
  size_t bufsize;
  size_t off;
  unsigned char *buffer;
};


/* Flush pending buffers. */
static int
buffered_flush (cdk_writer_t w)
{
  buffered_writer_t buf = (buffered_writer_t)cdk_writer_get_opaque (w);

  /* No pending buffers. */
  if (!buf->off)
    return 0;

  _cdk_log_debug ("buffered: flush %d octets\n", buf->off);
  if (!_cdk_writer_write_next (w, buf->buffer, buf->off))
    return -1;
  
  /* Reset offset after flush. */
  buf->off = 0;
  return 0;
}


static int
buffered_write (cdk_writer_t w, void *ctx, const void *buffer, size_t buflen)
{
  buffered_writer_t buf = (buffered_writer_t)ctx;
  size_t orig_buflen = buflen;
  size_t nwrite;
  
  while (buflen > 0)
    {
      nwrite = buflen > buf->bufsize? buf->bufsize : buflen;
      
      /* If the buffer is filled, flush it first. */
      if (nwrite  > (buf->bufsize - buf->off))
	{
	  _cdk_log_debug ("buffered: write flush\n");
	  buffered_flush (w);
	}
  
      memcpy (buf->buffer + buf->off, buffer, nwrite);
      buf->off += nwrite;
      buflen -= nwrite;
    }  
  return orig_buflen;
}


static int
buffered_release (void *ctx)
{
  buffered_writer_t buf = (buffered_writer_t)ctx;
  
  _cdk_log_debug ("buffered_close: %d octets\n", buf->bufsize);
  cdk_free (buf->buffer);
  cdk_free (buf);
  
  return 0;
}


static int
buffered_init (void **r_ctx)
{
  buffered_writer_t buf;
  
  buf = cdk_calloc (1, sizeof *buf);
  if (!buf)
    return CDK_Out_Of_Core;
  buf->bufsize = 4096;
  buf->buffer = cdk_calloc (1, buf->bufsize);
  if (!buf->buffer)
    {
      cdk_free (buf);
      return CDK_Out_Of_Core;
    }  
  *r_ctx = buf;
  return 0;
}


cdk_error_t
buffered_writer_new (buffered_writer_t *r_buf)
{
  cdk_error_t err;
  void *buf;
  
  err = buffered_init (&buf);
  if (err)
    return err;
  *r_buf = (buffered_writer_t)buf;
  return 0;
}


/* Set the size of the buffer for the buffered writer. */
cdk_error_t
buffered_writer_set_bufsize (buffered_writer_t buf, size_t bufsize)
{
  buf->bufsize = bufsize;
  cdk_free (buf->buffer);
  buf->buffer = cdk_calloc (1, bufsize);
  if (!buf->buffer)
    return CDK_Out_Of_Core;
  return 0;
}



cdk_error_t
cdk_writer_buffered_new (cdk_writer_t *r_wr, cdk_writer_t next,
			 buffered_writer_t buf)
{
  return cdk_writer_new (r_wr, next, &buffered_writer, buf);
}


struct cdk_writer_cbs_s buffered_writer =
{buffered_write, buffered_flush, buffered_release, buffered_init};
