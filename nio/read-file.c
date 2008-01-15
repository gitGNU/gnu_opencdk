/* reader-file.c - File reader
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


/* File reader context. */
struct file_reader_s
{
  FILE *fp;
};


/* Callback to read from a file. */
static int
file_read (cdk_reader_t r, void *ctx, void *buf, size_t buflen)
{
  file_reader_t f = (file_reader_t)ctx;
  
  return fread (buf, 1, buflen, f->fp);
}


/* Callback to close a file. */
static int
file_release (void *ctx)
{
  file_reader_t f = (file_reader_t)ctx;
  int err = 0;
  
  _cdk_log_debug ("file_release: fd=%d\n", f->fp? fileno (f->fp) : -1);
  if (f->fp != NULL)
    err = fclose (f->fp);
  cdk_free (f);
  
  return err;
}


/* Allocate new file context. */
static int
file_init (void **r_ctx)
{
  file_reader_t f;
  
  f = cdk_calloc (1, sizeof *f);
  if (!f)
    return CDK_Out_Of_Core;
  *r_ctx = f;
  return 0;
}



/* Associate a file with the given reader context. */
cdk_error_t
file_reader_set_filename (file_reader_t f, const char *filename)
{
  if (f->fp != NULL)
    fclose (f->fp);
  f->fp = fopen (filename, "rb");
  if (!f->fp)
    return CDK_File_Error;
  return 0;
}


/* Return the size of the associated file. */
cdk_error_t
file_reader_get_filesize (file_reader_t f, off_t *r_fsize)
{
  struct stat stbuf;
  
  if (!f || !r_fsize)
    return CDK_Inv_Value;
  
  if (fstat (fileno (f->fp), &stbuf))
    return CDK_File_Error;
  *r_fsize = stbuf.st_size;
  return 0;
}


/* Allocate a new file reader context and associate it with
   the given file. */
cdk_error_t
file_reader_new (file_reader_t *r_fp, const char *file)
{
  void *fp;
  cdk_error_t err;

  *r_fp = NULL;
  err = file_init (&fp);
  if (err)
    return err;
  
  err = file_reader_set_filename ((file_reader_t)fp, file);
  if (err)
    {
      file_release (fp);
      return err;
    }
  *r_fp = (file_reader_t)fp;
  return 0;
}


/**
 * cdk_reader_file_new:
 * @r_rd: the new reader object
 * @file: the file reader context
 * 
 * Allocate a new file reader object and open it.
 **/
cdk_error_t
cdk_reader_file_new (cdk_reader_t *r_rd, file_reader_t file)
{
  return cdk_reader_new (r_rd, NULL, &file_reader, file);
}


/* Module handle for the file reader context. */
struct cdk_reader_cbs_s file_reader =
{file_read, file_release, file_init};
