#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <opencdk.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <gcrypt.h>
#include <ctype.h>
#include <time.h>

#include "new-io.h"
#include "t-support.h"
#include "t-glue.h"


/* Create a literal packet with the given length and arbitrary data. */
static char*
make_random_litfile (const char *name, size_t len)
{
  FILE *fp;
  char *outname = make_tempname (name);
  unsigned char pkthead[12];
  time_t t = time (NULL);
  
  fp = fopen (outname, "wb");
  if (!fp)
    return NULL;
  
  len += 6;  
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
  fwrite (pkthead, 1, 12, fp);  
  len -= 6;
  
  while (len-- > 0)
    fputc (random () % 256, fp);
  
  fclose (fp);
  return outname;
}


int test_file_writer (void)
{
  struct stat stbuf;
  cdk_writer_t wr;
  cdk_error_t err;
  file_writer_t fp;
  char out[256];
  int n;
  
  strcpy (out, make_tempname ("out"));
  err = file_writer_new (&fp, out);
  if (err)
    goto fail;
  
  err = cdk_writer_file_new (&wr, fp);
  if (err)
    goto fail;
  
  n = cdk_writer_write (wr, "test", 4);
  if (n != 4)
    {
       cdk_writer_close (wr);
      goto fail;
    }  
  
  err = cdk_writer_close (wr);
  if (err)
    goto fail;
  
  if (stat (out, &stbuf) || stbuf.st_size != 4)
    goto fail;
  unlink (out);
  return 0;
  
  fail:
  unlink (out);
  return 1;
}


int test_buffered_writer (void)
{  
  cdk_writer_t wr, file;
  cdk_error_t err;
  file_writer_t fp;
  buffered_writer_t buf;
  unsigned char buffer[129];
  const char *s;
  int n, i;
  
  err = file_writer_new (&fp, make_tempname ("out2"));
  if (err)
    return err;
  err = cdk_writer_file_new (&file, fp);
  if (err)    
    return 1;
  
  err = buffered_writer_new (&buf);
  if (err)
    {
      cdk_writer_close (file);
      return 1;
    }
  buffered_writer_set_bufsize (buf, sizeof (buffer));
  
  err = cdk_writer_buffered_new (&wr, file, buf);
  if (err)
    {
      cdk_writer_close (file);
      return 1;
    }
  
  memset (buffer, 'A', sizeof (buffer));
  for (i=0; i < 4; i++)
    {      
      s = "look if this is really cached";
      n = cdk_writer_write (wr, s, strlen (s));
      if (n != strlen (s))
	{
	  cdk_writer_close (wr);
	  cdk_writer_close (file);
	  return -1;
	}
    }
  
  n = cdk_writer_write (wr, buffer, sizeof (buffer));
  if (n != sizeof (buffer))
    {
      cdk_writer_close (wr);
      cdk_writer_close (file);
      return -1;
    }  
  
  cdk_writer_close (wr);
  err = cdk_writer_close (file);
  
  return err;
}



int test_file_reader (void)
{
  cdk_reader_t rd;
  cdk_error_t err;
  file_reader_t fp;
  char buf[4], in[256];
  int n;
  FILE *fd;
  
  strcpy (in, make_tempname ("out"));
  fd = fopen (in, "wb");
  if (!fd)
    return -1;
  fwrite ("test", 1, 4, fd);
  fclose (fd);
      
  err = file_reader_new (&fp, in);
  if (!err)
    err = cdk_reader_file_new (&rd, fp);
  if (err)
    return -1;
  
  n = cdk_reader_read (rd, buf, 4);
  if (n != 4)
    {
      cdk_reader_close (rd);
      return 1;
    }  
  
  err = cdk_reader_close (rd);
  if (err)
    return -1;
  
  return 0;
}

int test_reader_writer (void)
{
  struct stat stbuf;
  cdk_reader_t rd;
  cdk_writer_t wr;
  cdk_error_t err;
  file_writer_t fp;
  file_reader_t fin;
  unsigned char buf[32];
  size_t file_len;
  int n;
  
  if (stat (make_tempname ("out2"), &stbuf))
    return 1;
  file_len = stbuf.st_size;
  
  err = file_reader_new (&fin, make_tempname ("out2"));
  if (!err)
    err = cdk_reader_file_new (&rd, fin);
  if (err)
    return 1;
  
  err = file_writer_new (&fp, make_tempname ("new-out"));
  if (err)
    {
      cdk_reader_close (rd);
      return 1;
    }  
  err = cdk_writer_file_new (&wr, fp);
  if (err)
    {
      cdk_reader_close (rd);
      return 1;
    }
  
  for (;;)
    {
      n = cdk_reader_read (rd, buf, 32);
      if (!n)
	break;
      cdk_writer_write (wr, buf, n);
    }  

  err = cdk_writer_close (wr);
  if (err)
    {      
      cdk_reader_close (rd);
      return err;
    }
  
  err = cdk_reader_close (rd);
  
  if (stat (make_tempname ("new-out"), &stbuf) || stbuf.st_size != file_len)
    return 1;
  return err;
}

struct my_cb_s
{
  char hello[42];
  size_t off;
};

static int my_init (void **r_ctx)
{
  *r_ctx = NULL;
  return 0;
}


static int my_flush (cdk_writer_t w)
{
  return 0;
}


static int my_release (void *ctx)
{
  struct my_cb_s *my = (struct my_cb_s*)ctx;
  
  return 0;
}

static int my_write (cdk_writer_t w, void *ctx, const void *buf, size_t buflen)
{
  struct my_cb_s *cb = (struct my_cb_s*)ctx;
  cdk_writer_t next;
  const char *buffer = (const char*)buf;
  char tmp[1];
  size_t i;
    
  next = cdk_writer_get_next (w);
  /*cbs = cdk_writer_get_cbs (w, &next_ctx);*/
  /*fprintf (stderr, "my_write: got %d bytes next %p\n", buflen, next);*/
  for (i=0; i < buflen; i++)
    {
      if (cb->off < 14 || !isalpha (buffer[i]))
	tmp[0] = buffer[i];
      else
	tmp[0] = toupper (buffer[i]);
      cdk_writer_write (next, tmp, 1);
      cb->off++;
    }  
  return buflen;
}

  
int test_user_writer (void)
{
  struct my_cb_s my;
  struct stat stbuf;
  cdk_error_t err;
  cdk_reader_t r;
  cdk_writer_t w, f;
  file_writer_t fp;
  file_reader_t fin;
  struct cdk_writer_cbs_s cbs;
  char buf[64];
  int n, file_len;

  if (stat (make_filename ("test-data.lit"), &stbuf))
    return 1;
  file_len = stbuf.st_size;
  
  err = file_reader_new (&fin, make_filename ("test-data.lit"));
  if (!err)
    err = cdk_reader_file_new (&r, fin);
  if (err)
    return 1;
  
  err = file_writer_new (&fp, make_tempname ("test-filter-out"));
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  err = cdk_writer_file_new (&w, fp);
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  memset (&my, 0, sizeof (my));
  strcpy (my.hello, "42 is the answer");
  memset (&cbs, 0, sizeof (cbs));
  cbs.init = my_init;
  cbs.release = my_release;
  cbs.write = my_write;
  cbs.flush = my_flush;
  err = cdk_writer_new (&f, w, &cbs, &my);
  if (err)
    {
      cdk_reader_close (r);
      cdk_writer_close (w);
      return 1;
    }
  
  for (;;)
    {
      n = cdk_reader_read (r, buf, 64);
      if (!n)
	break;
      cdk_writer_write (f, buf, n);
    }  
  
  cdk_reader_close (r);
  cdk_writer_close (f);
  cdk_writer_close (w);
  
  if (stat (make_tempname ("test-filter-out"), &stbuf) || 
      stbuf.st_size != file_len)
    return 1;
  
  return err;
}


int test_compress_writer2 (void)
{
#ifdef HAVE_LIBZ  
  struct stat stbuf;
  cdk_reader_t r;
  cdk_writer_t w, c;
  cdk_error_t err;
  file_writer_t fp;
  file_reader_t fin;
  compress_writer_t zip;
  unsigned char buf[256];
  int n, len;
  
  if (stat (make_filename ("test-data-red"), &stbuf))
    return 1;
  len = stbuf.st_size;
  
  err = file_reader_new (&fin, make_filename ("test-data-red"));
  if (!err)
    err = cdk_reader_file_new (&r, fin);
  if (err)
    return 1;
  
  err = file_writer_new (&fp, make_tempname ("test-filter-out-1"));
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }  
  
  err = cdk_writer_file_new (&w, fp);
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  err = compress_writer_new (&zip, 1);
  if (!err)
    err = cdk_writer_compress_new (&c, w, zip);
  if (err)
    {
      cdk_reader_close (r);
      cdk_writer_close (w);
      return 1;
    }
  
  len += 6; /* fixed header */
  len -= 192;
  buf[0] = 0xc0|11;
  buf[1] = (len / 256) + 192;
  buf[2] = len % 256;
  buf[3] = 'b';
  buf[4] = 0; /* no filename */
  buf[5] = (1179410208 >> 24) & 0xff;
  buf[6] = (1179410208 >> 16) & 0xff;
  buf[7] = (1179410208 >> 8) & 0xff;
  buf[8] = (1179410208 >> 0) & 0xff;
  cdk_writer_write (c, buf, 9);
  
  for (;;)
    {
      n = cdk_reader_read (r, buf, sizeof (buf));
      if (!n)
	break;
      cdk_writer_write (c, buf, n);
    }
  
  cdk_reader_close (r);
  cdk_writer_close (c);
  cdk_writer_close (w);
  
  return err;
#else
  return 0;
#endif
}

int test_compress_writer (void)
{
#ifdef HAVE_LIBZ  
  cdk_reader_t r;
  cdk_writer_t w, c;  
  cdk_error_t err;
  file_writer_t fp;
  file_reader_t fin;
  compress_writer_t zip;
  unsigned char buf[128];
  int n;
  
  err = file_reader_new (&fin, make_filename ("test-data.lit"));
  if (!err)
    err = cdk_reader_file_new (&r, fin);
  if (err)
    return 1;
  
  err = file_writer_new (&fp, make_tempname ("test-filter-out-2"));
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  err = cdk_writer_file_new (&w, fp);
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  err = compress_writer_new (&zip, 1);
  if (!err)
    err = cdk_writer_compress_new (&c, w, zip);
  if (err)
    {
      cdk_reader_close (r);
      cdk_writer_close (w);
      return 1;
    }
  
  for (;;)
    {
      n = cdk_reader_read (r, buf, 128);
      if (!n)
	break;
      cdk_writer_write (c, buf, n);
    }
  
  cdk_reader_close (r);
  cdk_writer_close (c);
  cdk_writer_close (w);
  
  return err;
#else
  return 0;
#endif  
}


int test_writer_armor (void)
{
  struct stat stbuf;
  cdk_error_t err;
  cdk_reader_t r;
  cdk_writer_t w, a;
  file_writer_t fp;
  file_reader_t fin;
  armor_writer_t arm;
  int n, len;
  unsigned char buf[128];  
  
  if (stat (make_filename ("test-data-red"), &stbuf))
    return 1;
  len = stbuf.st_size;
  
  err = file_reader_new (&fin, make_filename ("test-data-red"));
  if (!err)
    err = cdk_reader_file_new (&r, fin);
  if (err)
    return 1;
  
  err = file_writer_new (&fp, make_tempname ("test-filter-out-3"));
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  err = cdk_writer_file_new (&w, fp);
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  err = armor_writer_new (&arm, 0);
  if (!err)
    err = cdk_writer_armor_new (&a, w, arm);
  if (err)
    {
      cdk_reader_close (r);
      cdk_writer_close (w);
      return 1;
    }
  
  len += 6; /* fixed header */
  len -= 192;
  buf[0] = 0xc0|11;
  buf[1] = (len / 256) + 192;
  buf[2] = len % 256;
  buf[3] = 'b';
  buf[4] = 0; /* no filename */
  buf[5] = (1179410208 >> 24) & 0xff;
  buf[6] = (1179410208 >> 16) & 0xff;
  buf[7] = (1179410208 >> 8) & 0xff;
  buf[8] = (1179410208 >> 0) & 0xff;
  cdk_writer_write (a, buf, 9);
  
  for (;;)
    {
      n = cdk_reader_read (r, buf, sizeof (buf));
      if (!n)
	break;
      cdk_writer_write (a, buf, n);
    }
  
  cdk_reader_close (r);
  cdk_writer_close (a);
  cdk_writer_close (w);
  return 0;
}


int test_error (void)
{
  cdk_error_t err;
  file_reader_t fp;
  
  err = file_reader_new (&fp, make_tempname ("bla-fasel-blubbber"));
  if (err == CDK_File_Error || errno == ENOENT)
    return 0;
  
  return 1;
}


int test_digest_reader (void)
{
  unsigned char mdbuf[] = /* SHA1 hash of 'test-data */
    {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 
     0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8,
     0x07, 0x09 };
  
  unsigned char mdcheck[20];
  cdk_error_t err;
  cdk_reader_t r, m;
  digest_reader_t dh;
  file_reader_t fp;
  gcry_md_hd_t md;
  int n;
  unsigned char buf[256];
  
  err = file_reader_new (&fp, make_filename ("test-data"));
  if (!err)
    err = cdk_reader_file_new (&r, fp);
  if (err)
    return 1;
  
  err = digest_reader_new (&dh, GCRY_MD_SHA1);
  if (!err)
    err = cdk_reader_digest_new (&m, r, dh);
  if (err)
    {
      cdk_reader_close (r);
      return 1;
    }
  
  for (;;)
    {
      n = cdk_reader_read (m, buf, sizeof (buf));
      if (!n)
	break;
    }
  
  err = digest_reader_get_handle (dh, &md);
  
  cdk_reader_close (r);
  cdk_reader_close (m);
  
  if (err)
    {
      gcry_md_close (md);
      return 1;
    }  
  
  /*for (i=0; i < 20; i++) printf ("%02X", mdbuf[i]);
  printf ("\n");*/
  memcpy (mdcheck, gcry_md_read (md, 0), 20);
  /*for (i=0; i < 20; i++) printf ("%02X", mdcheck[i]);
  printf ("\n");*/
  gcry_md_close (md);
  if (memcmp (mdcheck, mdbuf, 20))
    return 1;
  
  return 0;
}


int
test_auto_chain (void)
{
#ifdef HAVE_LIBZ  
  cdk_reader_t rd;
  cdk_writer_t wr;
  cdk_error_t err;
  file_writer_t fp;
  file_reader_t fin;
  compress_writer_t zip;
  armor_writer_t arm;
  unsigned char buf[512];
  int i;
    
  err = file_writer_new (&fp, make_tempname ("test-chain-out"));
  if (err)
    return 1;
  
  err = cdk_writer_file_new (&wr, fp);
  if (err)
    return 1;
  
  err = armor_writer_new (&arm, 0);
  if (!err)
    err = cdk_writer_attach (wr, &armor_writer, arm);
  if (err)
    {
      cdk_writer_close (wr);
      return 1;
    }
  
  err = compress_writer_new (&zip, CDK_COMPRESS_ZIP);
  if (!err)
    err = cdk_writer_attach (wr, &compress_writer, zip);
  if (err)
    {
      cdk_writer_close (wr);
      return 1;
    }  
  
  err = file_reader_new (&fin, make_filename ("test-data.lit"));
  if (!err)
    err = cdk_reader_file_new (&rd, fin);
  if (err)
    {
      cdk_writer_close (wr);
      return 1;
    }
  
  for (;;)
    {
      i = cdk_reader_read (rd, buf, sizeof (buf));
      if (!i)
	break;
      cdk_writer_write (wr, buf, i);
    }  
  
  cdk_writer_close (wr);
  cdk_reader_close (rd);
  return err;
#else
  return 0;
#endif
}


int test_fmt_data (void)
{
  cdk_reader_t r;
  cdk_error_t err;
  file_reader_t fp;
  int n = 4, len;
  char buf[256];
  
  err = file_reader_new (&fp, make_filename ("test-data-fmt"));
  if (!err)
    err = cdk_reader_file_new (&r, fp);
  if (err)
    return 1;
  
  for (;;)
    {
      len = cdk_reader_readline (r, buf, sizeof (buf));
      /*printf ("line len %d = '%s'\n", len, buf);*/
      if (len < 0)
	break;
      n--;
    }
  
  err = 0;
  if (n != 0)
    err = 1;  
  
  cdk_reader_close (r);
  return err;
}


int test_buffer_writer (void)
{
  cdk_writer_t w;
  cdk_error_t err;
  buffer_writer_t buf;
  int n;
  unsigned char *raw = NULL;
  size_t rawlen;
  
  err = buffer_writer_new (&buf);
  if (!err)
    err = cdk_writer_buffer_new (&w, buf);
  if (err)
    {
      cdk_writer_close (w);
      return 1;
    }  
  
  for (n = 0; n < 1100;)
    {      
      n += cdk_writer_write (w, "test", 4);
      if (!n)
	{
	  cdk_writer_close (w);
	  return 1;
	}
    }  
  
  buffer_writer_get_data (buf, &raw, &rawlen);
  if (!raw || rawlen != n)
    err = 1;
  
  cdk_free (raw);
  cdk_writer_close (w);
  return err;
}

int test_cipher_writer (const char *infile, const char *outfile)
{
  const int bufsize = 2048;
  const unsigned char symkey_enc[] = 
    {0x8C, 0x04, 0x04, 0x07, 00, 0x03};
  cdk_s2k_t s2k;
  cdk_dek_t dek;
  cdk_error_t err;
  cdk_writer_t out;
  cdk_reader_t in;
  file_reader_t fin;
  file_writer_t fout;
  cipher_writer_t c;
  unsigned char buf[bufsize];
  int n;
  
  err = cdk_s2k_new (&s2k, 0, CDK_MD_RMD160, NULL);
  if (err)
    return 1;
  
  err = cdk_dek_from_passphrase (&dek, CDK_CIPHER_AES, s2k, 0, "abc");
  if (err)
    {
      cdk_s2k_free (s2k);
      return 1;
    }
  cdk_dek_set_mdc_flag (dek, 1);
  
  err = file_writer_new (&fout, outfile);
  if (!err)
    err = cdk_writer_file_new (&out, fout);
  if (err)
    goto leave;
  if (!cdk_writer_write (out, symkey_enc, sizeof (symkey_enc)))
    {
      err = CDK_Inv_Value;
      goto leave;
    }
  err = cipher_writer_new (&c, bufsize);
  if (!err)
    err = cipher_writer_set_dek (c, dek);
  if (!err)
    err = cdk_writer_attach (out, &cipher_writer, c);
  if (err)
    goto leave;
  
  err = file_reader_new (&fin, infile);
  if (!err)
    err = cdk_reader_file_new (&in, fin);
  if (err)
    goto leave;
  
  for (;;)
    {
      n = cdk_reader_read (in, buf, bufsize);
      if (!n)
	break;
      cdk_writer_write (out, buf, n);
    }  

  leave:
  cdk_reader_close (in);
  cdk_writer_close (out);
  cdk_s2k_free (s2k);
  cdk_dek_free (dek);
  
  return err;
}

  
int test_large_cipher (void)
{
  char in_name[512];
  int err;
  
  strcpy (in_name, make_random_litfile ("test-l-in-cipher", 92851));  
  err = test_cipher_writer (in_name, make_tempname ("test-l-cipher-out"));
  
  return err;
}


int test_buffer_reader (void)
{
  buffer_reader_t br;
  cdk_reader_t rd;
  cdk_error_t err;
  char tmp[32];
  int n;
  
  err = buffer_reader_new (&br, "test", 4);
  if (err)
    return 1;
  
  err = cdk_reader_buffer_new (&rd, br);
  if (err)
    return 1;
  
  n = cdk_reader_read (rd, tmp, 32);
  if (n != 4)
    err = 1;
  else if (tmp[0] != 't' || tmp[1] != 'e' || tmp[2] != 's' || tmp[3] != 't')
    err = 1;
  
  cdk_reader_close (rd);
  
  err = buffer_reader_new (&br, "123456789", 9);
  if (err)
    return 1;
  err = cdk_reader_buffer_new (&rd, br);
  if (err)
    return 1;
  
  n = cdk_reader_read (rd, tmp, 3);
  if (n != 3 || tmp[0] != '1' || tmp[1] != '2' || tmp[2] != '3')
    {
      cdk_reader_close (rd);
      return 1;
    }
  
  n = cdk_reader_read (rd, tmp, 6);
  if (n != 6)
    err = 1;
  else
    {
      n = cdk_reader_read (rd, tmp, 32);
      if (n != 0)
	err = 1;
    }  
  
  cdk_reader_close (rd);
  
  return err;
}


int main (int argc, char **argv)
{
  int err;
  
  err = test_file_writer ();
  if (err)
    {
      fprintf (stderr, "test: file_writer FAILED\n");
      return 1;
    }  
  
  err = test_buffered_writer ();
  if (err)
    {
      fprintf (stderr, "test: buffered_writer FAILED\n");
      return 1;
    }
  
  err = test_file_reader ();
  if (err)
    {
      fprintf (stderr, "test: file reader FAILED\n");
      return 1;
    }
  
  err = test_reader_writer ();
  if (err)
    {
      fprintf (stderr, "test: reader writer FAILED\n");
      return 1;
    }
  
  err = test_error ();
  if (err)
    {
      fprintf (stderr, "test: error FAILED\n");
      return 1;
    }
  
  err = test_user_writer ();
  if (err)
    {
      fprintf (stderr, "test: user writer FAILED\n");
      return 1;
    }
  
  err = test_compress_writer ();
  if (err)
    {
      fprintf (stderr, "test: compress writer FAILED\n");
      return 1;
    }
  
  err = test_compress_writer2 ();
  if (err)
    {
      fprintf (stderr, "test: compress redundant FAILED\n");
      return 1;
    }
  
  err = test_writer_armor ();
  if (err)
    {
      fprintf (stderr, "test: armor writer FAILED\n");
      return 1;
    }  
  
  err = test_digest_reader ();
  if (err)
    {
      fprintf (stderr, "test: digest reader FAILED\n");
      return 1;
    }
  
  err = test_auto_chain ();
  if (err)
    {
      fprintf (stderr, "test: auto chain FAILED\n");
      return 1;
    }

  err = test_fmt_data ();
  if (err)
    {
      fprintf (stderr, "test: formatted data FAILED\n");
      return 1;
    }  
 
  
  err = test_buffer_writer ();
  if (err)
    {
      fprintf (stderr, "test: buffer writer FAILED\n");
      return 1;
    }
  
  err = test_cipher_writer (make_filename ("test-data.lit"),
			    make_tempname ("test-cipher-out"));
  if (err)
    {
      fprintf (stderr, "test: cipher writer FAILED\n");
      return 1;
    }

  err = test_buffer_reader ();
  if (err)
    {
      fprintf (stderr, "test: buffer reader FAILED\n");
      return 1;
    }
  
  
  err = test_large_cipher ();
  if (err)
    {
      fprintf (stderr, "test: cipher writer large FAILED\n");
      return 1;
    }  
  
  return 0;
}
