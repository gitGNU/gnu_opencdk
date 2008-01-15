/* writer.c - Generic writer functions
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


/* Generic writer context. */
struct cdk_writer_s
{
  struct cdk_writer_cbs_s cbs;
  struct cdk_writer_s *next;
  struct cdk_writer_s *last;
  void *cbs_ctx;  
};


/**
 * cdk_writer_get_next:
 * @: writer object
 * 
 * Return the next writer in the chain or NULL. 
 **/
cdk_writer_t
cdk_writer_get_next (cdk_writer_t w)
{
  if (!w)
    return NULL;
  return w->next;
}


/**
 * cdk_writer_get_cbs:
 * @w: writer object
 * @r_ctx: will store optionally the context
 * 
 * Return the writer callback set. 
 **/
cdk_writer_cbs_t
cdk_writer_get_cbs (cdk_writer_t w, void **r_ctx)
{
  if (!w)
    return NULL;
  *r_ctx = w->cbs_ctx;
  return &w->cbs;
}


/**
 * cdk_writer_get_opaque:
 * @w: writer object
 * 
 * Return the opaque object stored in the writer. 
 **/
void*
cdk_writer_get_opaque (cdk_writer_t w)
{
  if (!w)
    return NULL;
  return w->cbs_ctx;
}


/**
 * cdk_writer_attach:
 * @root: root writer object
 * @cbs: callback function structure
 * @cbs_ctx: opaque context
 * 
 * Attach a new writer to the root.
 * The writer is allocated internally, the call has to provide
 * the appropriate callback function set and the context.
 **/
cdk_error_t
cdk_writer_attach (cdk_writer_t root, cdk_writer_cbs_t cbs, void *cbs_ctx)
{
  cdk_writer_t n;
  cdk_error_t err;
  
  /* If there is no last writer, we use this is a self reference.
     And attach the new writer to the last writer object. */
  err = cdk_writer_new (&n, root->last? root->last : root, cbs, cbs_ctx);
  if (err)
    return err;
  
  root->last = n;  
  return 0;
}


/**
 * cdk_writer_new:
 * @r_wr: will contain the new writer object
 * @next: pointer to next writer in the chain
 * @cbs: the callback functions
 * 
 * Allocate a new writer with the given callbacks.
 **/
cdk_error_t
cdk_writer_new (cdk_writer_t *r_wr, cdk_writer_t next,
		cdk_writer_cbs_t cbs, void *cbs_ctx)
{
  cdk_writer_t wr;

  if (!r_wr || !cbs || !cbs_ctx)
    return CDK_Inv_Value;
  
  *r_wr = NULL;
  wr = cdk_calloc (1, sizeof *wr);
  if (!wr)
    return CDK_Out_Of_Core;

  wr->next = next;
  wr->cbs_ctx = cbs_ctx;
  wr->cbs.write = cbs->write;
  wr->cbs.flush = cbs->flush;
  wr->cbs.release = cbs->release;
  
  *r_wr = wr;
  return 0;
}


/* Adjusted code for the writer chain mode. */
static cdk_error_t
writer_auto_close (cdk_writer_t wr)
{
  cdk_writer_t n, t;
  cdk_error_t err;
  
  /* Make sure all writers will flush their contents. */
  for (n = wr->last; n; n = n->next)
    { 
      err = n->cbs.flush (n);
      if (err)
	break;
    }
  
  n = wr->last;
  while (n != NULL)
    {
      t = n->next;
      n->cbs.release (n->cbs_ctx);
      cdk_free (n);
      n = t;
    }
  
  return 0;
}


/**
 * cdk_writer_close:
 * @w: writer object
 * 
 * Close the writer and flush all pending buffers. 
 **/
cdk_error_t
cdk_writer_close (cdk_writer_t wr)
{
  int err;
  
  if (!wr)
    return CDK_Inv_Value;  
  
  /* If we have a chain of writers, the way to release them
     is different compared to the single version. */
  if (wr->last)
    return writer_auto_close (wr);
  
  err = wr->cbs.flush (wr);
  wr->cbs.release (wr->cbs_ctx);
  cdk_free (wr);
  return err? CDK_File_Error : 0;
}


/**
 * cdk_writer_write:
 * @wr: writer object
 * @buf: buffer to write
 * @buflen: lenght of the buffer
 * 
 * Write the contents of the buffer into the writer.
 **/
int
cdk_writer_write (cdk_writer_t wr, const void *buf, size_t buflen)
{
  cdk_writer_t out;
  void *out_ctx;
  
  if (!wr)
    return -1;
  
  /* If the writer is nested, which means it contains other writer
     callbacks, we need to write the data to the last writer which
     were added. Otherwise is is directly written to the current writer. */
  out = wr->last? wr->last : wr;
  out_ctx = wr->last? wr->last->cbs_ctx : wr->cbs_ctx;
  
  return out->cbs.write (out, out_ctx, buf, buflen);
}


int
_cdk_writer_write_next (cdk_writer_t wr, const void *buf, size_t buflen)
{
  cdk_writer_t next = wr->next;
  void *next_ctx = next->cbs_ctx;
  
  return next->cbs.write (next, next_ctx, buf, buflen);
}



/**
 * cdk_writer_flush:
 * @wr: writer object
 * 
 * Flush all pending buffers. 
 **/
cdk_error_t
cdk_writer_flush (cdk_writer_t wr)
{
  if (!wr)
    return CDK_Inv_Value;
  
  if (wr->cbs.flush (wr))
    return CDK_File_Error;
  return 0;
}
