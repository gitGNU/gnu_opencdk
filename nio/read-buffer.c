/* reader-buffer.c - Buffer reader
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
#include <sys/stat.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"


struct buffer_reader_s
{
  unsigned char *buf;
  size_t len;
  size_t pos;
};


/* Return the buffer size relative to the position. */
#define buffer_get_len(buf) ((buf)->len - (buf)->pos)

int 
buffer_read (cdk_reader_t r, void *ctx, void *buf, size_t buflen)
{
  buffer_reader_t br = (buffer_reader_t)ctx;
  
  if (!buffer_get_len (br))
    return 0; /* EOF */
  
  /* If the user requested more data than available, set buflen
     to the maximal amount of available data. */
  if (buflen > buffer_get_len (br))
    buflen = buffer_get_len (br);
  
  memcpy (buf, br->buf, buflen);
  br->pos += buflen;
  
  return buflen;
}


int
buffer_release (void *ctx)
{
  buffer_reader_t br = (buffer_reader_t)ctx;
  
  cdk_free (br->buf);
  br->len = 0;
  br->pos = 0;
  
  return 0;
}

int 
buffer_init (void **r_ctx)
{
  buffer_reader_t br;
  
  /* It is not clear how large the buffer needs to be, so we
     cannot allocated it here. */
  br = cdk_calloc (1, sizeof *br);
  *r_ctx = (buffer_reader_t)br;
  
  return 0;
}



cdk_error_t
buffer_reader_new (buffer_reader_t *r_ctx,
		   const void *buf, size_t buflen)
{
  cdk_error_t err;
  buffer_reader_t ctx;
  void *br;
  
  if (!r_ctx || !buflen)
    return CDK_Inv_Value;
  *r_ctx = NULL;
  
  err = buffer_init (&br);
  if (err)
    return err;
  
  ctx = (buffer_reader_t)br;
  ctx->buf = cdk_calloc (1, buflen);
  ctx->len = buflen;
  memcpy (ctx->buf, buf, buflen);
  *r_ctx = ctx;
  
  return 0;
}


cdk_error_t
cdk_reader_buffer_new (cdk_reader_t *r_rd, buffer_reader_t buf)
{  
  return cdk_reader_new (r_rd, NULL, &buffer_reader, buf);
}


/* Module handle for the file reader context. */
struct cdk_reader_cbs_s buffer_reader =
{buffer_read, buffer_release, buffer_init};

