/* write-file.c
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


/* Writer with the ability to write a file. */
struct file_writer_s
{
  FILE *fp;
};


/* Custom write callback for the file writer. */
static int
file_write (cdk_writer_t w, void *ctx, const void *buf, size_t buflen)
{
  file_writer_t f = (file_writer_t)ctx;
  
  return fwrite (buf, 1, buflen, f->fp);
}


/* Custom release callback for the file writer. */
static int
file_release (void *ctx)
{
  file_writer_t f = (file_writer_t)ctx;
  int err;
  
  _cdk_log_debug ("file_close: fd=%d\n", fileno (f->fp));
  err = fclose (f->fp);
  cdk_free (f);
  return err;
}


/* Custom flush callback for the file writer. */
static int
file_flush (cdk_writer_t w)
{
  file_writer_t f = (file_writer_t)cdk_writer_get_opaque (w);
  
  _cdk_log_debug ("file_flush: done\n");
  return fflush (f->fp);
}


static int
file_init (void **r_ctx)
{
  file_writer_t f;
  
  f = cdk_calloc (1, sizeof *f);
  if (!f)
    return CDK_Out_Of_Core;
  *r_ctx = f;
  return 0;
}


/* Allocate a new file writer context and associate it with the
   given file name. */
cdk_error_t
file_writer_new (file_writer_t *r_fp, const char *filename)
{
  cdk_error_t err;
  void *fp;
  
  if (!r_fp)
    return CDK_Inv_Value;
  
  err = file_init (&fp);
  if (err)
    return err;
  
  *r_fp = (file_writer_t)fp;
  err = file_writer_set_filename (*r_fp, filename);
  return err;
}


/* Set (a new) file name for the given file writer. */
cdk_error_t
file_writer_set_filename (file_writer_t f, const char *filename)
{
  if (!f)
    return CDK_Inv_Value;
  
  if (f->fp != NULL)
    fclose (f->fp);
  f->fp = fopen (filename, "wb");
  if (!f->fp)
    return CDK_File_Error;
  return 0;
}


/**
 * cdk_writer_file_new:
 * @r_wr: the new allocated file writer
 * fp: the file writer object
 * 
 * Allocate a new writer based on a file.
 **/
cdk_error_t
cdk_writer_file_new (cdk_writer_t *r_wr, file_writer_t fp)
{
  cdk_error_t err;
  cdk_writer_t wr;
  
  if (!r_wr || !fp)
    return CDK_Inv_Value;
  
  *r_wr = NULL;
  err = cdk_writer_new (&wr, NULL, &file_writer, fp);
  if (err)
    return err;
  *r_wr = wr;
  return 0;
}


/* Module handle for the file routines. */
struct cdk_writer_cbs_s file_writer =
{file_write, file_flush, file_release, file_init};
