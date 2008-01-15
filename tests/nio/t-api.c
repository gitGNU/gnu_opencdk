#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#ifdef HAVE_LIBZ
#include "opencdk.h"
#include "main.h"
#include "new-io.h"
#include "t-support.h"
#include "t-glue.h"

static cdk_error_t
build_literal_packet (cdk_writer_t wr, const char *infile)
{
  struct stat stbuf;
  unsigned char pkthead[12];
  time_t t = time (NULL);
  size_t len;
  
  if (stat (infile, &stbuf))
    return CDK_Inv_Mode;
  
  len = stbuf.st_size+6;
  
  pkthead[0] = 0xC0|11;
  pkthead[1] = 0xff;
  pkthead[2] = len >> 24;
  pkthead[3] = len >> 16;
  pkthead[4] = len >>  8;
  pkthead[5] = len >>  0;
  pkthead[6] = 'b';
  pkthead[7] = 0;
  pkthead[8] = t >> 24;
  pkthead[9] = t >> 16;
  pkthead[10]= t >> 8;
  pkthead[11] = t>> 0;
  cdk_writer_write (wr, pkthead, 12);
  
  return 0;
}

  
  
/**
 * cdk_file_store:
 * @infile: the input file name
 * @outfile: the output file name.
 * 
 * Wrap a file in a literal packet and compress the data.
 **/
cdk_error_t
_cdk_file_store (const char *infile, const char *outfile)
{
  cdk_writer_t out = NULL;
  cdk_reader_t in = NULL;
  cdk_error_t err;
  file_writer_t fout;
  file_reader_t fin;
  compress_writer_t zip;
  unsigned char buf[512];
  int n;
  
  /* Create a simple file writer. */
  err = file_writer_new (&fout, outfile);
  if (!err)
    err = cdk_writer_file_new (&out, fout);
  if (err)
    goto fail;
  
  /* Push a compress reader into the filter chain. */
  err = compress_writer_new (&zip, CDK_COMPRESS_ZIP);
  if (!err)
    err = cdk_writer_attach (out, &compress_writer, zip);
  if (err)
    goto fail;
  
  /* Create a simple filer reader. */
  err = file_reader_new (&fin, infile);
  if (!err)
    err = cdk_reader_file_new (&in, fin);
  if (err)
    goto fail;
    
  /* Write the literal packet head into the out writer. */
  err = build_literal_packet (out, infile);
  if (err)
    goto fail;
  
  /* Read all data with the file reader, compress it with
     the pushed writer and write it to the file. */
  for (;;)
    {
      n = cdk_reader_read (in, buf, DIM (buf));
      if (n < 1)
	break;
      cdk_writer_write (out, buf, n);
    }  
  
  fail:
  cdk_writer_close (out);
  return err;
}


int main (int argc, char **argv)
{
  cdk_error_t err;  
  char in[256], out[256];
  
  /*cdk_set_log_level (CDK_LOG_DEBUG);*/
  
  strcpy (in, make_filename ());
  strcpy (out, make_tempname ());
  
  err = _cdk_file_store (in, out);
  unlink (out);
  if (err)
    {
      fprintf (stderr, "file store: FAILED\n");
      return 1;
    }
  
  return 0;
}
#else
int main (int argc, char **argv)
{
  return 0;
}
#endif
