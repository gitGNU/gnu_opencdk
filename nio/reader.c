/* reader.c - Generic reader functions
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
#include <string.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"


/* Generic reader context. */
struct cdk_reader_s
{
  struct cdk_reader_cbs_s cbs;
  struct cdk_reader_s *next;
  void *cbs_ctx;
};


void*
cdk_reader_get_opaque (cdk_reader_t rd)
{
  return rd->cbs_ctx;
}


cdk_reader_t
cdk_reader_get_next (cdk_reader_t rd)
{
  return rd->next;
}


int
_cdk_reader_read_next (cdk_reader_t rd, void *buf, size_t buflen)
{
  cdk_reader_t next = rd->next;
  void *cbs_ctx = next->cbs_ctx;
  
  return next->cbs.read (next, cbs_ctx, buf, buflen);
}

  
int
cdk_reader_read (cdk_reader_t rd, void *buf, size_t buflen)
{
  if (!rd)
    return -1;
  
  return rd->cbs.read (rd, rd->cbs_ctx, buf, buflen);
}


int
cdk_reader_readline (cdk_reader_t rd, void *buf, size_t buflen)
{
  unsigned char buffer[1];
  unsigned char *p = (unsigned char *)buf;
  int n;
  size_t pos;
  size_t nread; /* amount of bytes we read; includes control chars. */
  
  /* The return value 0 does not mean an error, but that we
     read an empty line (\n or \r\n for example). */
  
  p[0] = '\0';
  for (pos = 0, nread = 0;;)
    {
      n = cdk_reader_read (rd, buffer, 1);
      if (!n && nread > 0) /* It is no EOF if we read some chars before. */
	{
	  p[pos] = '\0';
	  return pos;
	}
      if ((!n && nread == 0) || n == -1)
	return -1; /* EOF or eror */
      buflen--;
      nread++;
      if (buffer[0] == '\r')
	continue;
      if (buflen-1 == 0 || buffer[0] == '\n')
	{
	  p[pos] = '\0';;
	  return pos;
	}
      p[pos++] = buffer[0];
    }
  p[pos] = '\0';

  return pos;
}
	

cdk_error_t
cdk_reader_close (cdk_reader_t rd)
{
  int err;
  
  if (!rd)
    return CDK_Inv_Value;
  
  err = rd->cbs.release (rd->cbs_ctx);
  cdk_free (rd);
  return err? CDK_File_Error: 0;
}


/**
 * cdk_reader_new:
 * @r_rd: new reader context
 * @next: next reader in the chain or NULL
 * @cbs: the callback structure
 * @cbs_ctx: the opaque handle for the callback structure
 * 
 * Allocate a new reader object.
 **/
cdk_error_t
cdk_reader_new (cdk_reader_t *r_rd, cdk_reader_t next,
		cdk_reader_cbs_t cbs, void *cbs_ctx)
{
  cdk_reader_t rd;
  
  if (!r_rd || !cbs || !cbs_ctx)
    return CDK_Inv_Value;
  
  *r_rd = NULL;
  rd = cdk_calloc (1, sizeof *rd);
  if (!rd)
    return CDK_Out_Of_Core;
  
  rd->next = next;
  rd->cbs_ctx = cbs_ctx;
  rd->cbs.read = cbs->read;
  rd->cbs.release = cbs->release;
  *r_rd = rd;
  
  return 0;
}
