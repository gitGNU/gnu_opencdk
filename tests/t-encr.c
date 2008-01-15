/* t-encr.c - regression test for ecnrypting and decrypting data.
 *    Copyright (C) 2007 Timo Schulz
 *
 * This file is part of OPENCDK.
 *
 * OPENCDK is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OPENCDK is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OPENCDK; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include <stdio.h>
#include <gcrypt.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "t-support.h"

/* Global error counter. */
static int err_cnt = 0;

struct encr_test_s
{
  const char *in_file;
  const char *pass;
  const char *key_file;
  int sym;
};

struct encr_test_s files[] = 
{
  {"plain-test-sym.gpg", "abc", NULL, 1},
  {"plain-test-pubenc.asc", "", "sec.gpg", 0},
  {"plain-test-pubenc-part.gpg", "", "sec.gpg", 0}, 
  {NULL, NULL}
};


struct encrypt_test_s
{
  const char *keyfile;
  const char *username;
  cdk_error_t expected;
};

/* Test list for the transform code. It contains a key file
   and the recipient which to chose. */
struct encrypt_test_s test_encr[] =
{
  {"pub.gpg", "opencdk", CDK_Success},
  {"newkey.gpg", "ralf", CDK_Unusable_Key},
  {NULL, NULL}
};

static const char *t_data_plain = 
  "hello, this is supposed to be signed.";

/* The data only contains a single literal packet with the data 'test\n'. */
static const char *t_data_literal =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"ywtiAEY1/sF0ZXN0Cg==\n"
"=mTsD\n"
"-----END PGP MESSAGE-----\n";

/* Contains 2 literal packets in the encryption packet which 
   violates the OpenPGP packet composition. */
static const char *t_data_literal_2 =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"jA0EBwMDrDdfDZqLFsVg0nABpYBb0Po1BAxBA+6Shtf/lown/Roy4XjhKqePujg0\n"
"noxjhYFlrHE/U5oeba2NPVW9nydLtYnnTatLp46coPyACatd9vcOLPGp8h2brqSy\n"
"LzjIxwRDVbA2FDpG6T4Fsdd6d6SOt9zjPBDSDniIUoKP\n"
"=tVr4\n"
"-----END PGP MESSAGE-----\n";

/* Literal data packet with no name. */
static const char *t_data_literal_noname = 
"-----BEGIN PGP MESSAGE-----\n"
"\n"  
"ywdiAAECAwRh\n"
"=2K0b\n"
"-----END PGP MESSAGE-----\n";


/* Simple passphrase callback with fixed pass. */
char* passphrase_cb (void *opa, const char *prompt)
{
  struct encr_test_s *one = (struct encr_test_s*)opa;
  const char *s = one->pass;
  
  /*printf ("get passphrase: '%s' = '%s'\n", prompt, s);*/
  return cdk_strdup (s);
}


static const char *all_recipients[] =  {
  "yankee", "gamma", "opencdk", "victor", "uniform", NULL };

static cdk_error_t tst_encr_all_recip_file (void)
{
  cdk_strlist_t recip;
  cdk_keydb_hd_t db;
  cdk_ctx_t ctx;
  cdk_error_t err;
  char out[256];
  int i;
  
  err = cdk_handle_new (&ctx);
  if (err)
    return err;
  
  err = cdk_keydb_new_from_file (&db, 0, make_filename ("pub.gpg"));
  if (err)
    {
      cdk_handle_free (ctx);
      return err;
    }
  

  cdk_handle_control (ctx, CDK_CTLF_SET, CDK_CTL_OVERWRITE, 1);
  cdk_handle_set_keydb (ctx, db);
  
  recip = NULL;
  for (i=0; all_recipients[i] != NULL; i++)    
    cdk_strlist_add (&recip, all_recipients[i]);
  
  strcpy (out, make_tempname ());
  err = cdk_file_encrypt (ctx, recip, make_filename ("plain-test.gpg"),
			  out);
  
  cdk_handle_free (ctx);
  cdk_keydb_free (db);
  cdk_strlist_free (recip);
  
  unlink (out);
  return err;
}


static cdk_error_t test_decr_one_file (struct encr_test_s *one)
{
  cdk_error_t err;
  cdk_keydb_hd_t db;
  cdk_ctx_t hd;
  char out[256];
  
  err = cdk_handle_new (&hd);
  if (err)
    return err;
  
  if (!one->sym)
    {
      err = cdk_keydb_new_from_file (&db, 1, make_filename (one->key_file));
      if (err)
	{
	  cdk_handle_free (hd);
	  return err;
	}
      
      cdk_handle_set_keydb (hd, db);
    }
  else
    db = NULL;
  
  strcpy (out, make_tempname ());
  cdk_handle_control (hd, CDK_CTLF_SET, CDK_CTL_OVERWRITE, 1);
  cdk_handle_set_passphrase_cb (hd, passphrase_cb, one);
  err = cdk_file_decrypt (hd, make_filename (one->in_file), out);
	  
  if (db != NULL)
    cdk_keydb_free (db);
  cdk_handle_free (hd);
  unlink (out);
  return err;
}


static cdk_error_t test_lit_no_name (void)
{
  struct stat stbuf;
  cdk_stream_t s;
  cdk_error_t err;
  cdk_ctx_t hd;
  char outname[256], inname[256];

  strcpy (inname, make_tempname ());
  err = cdk_stream_create (inname, &s);
  if (err)
    return err;
  
  cdk_stream_write (s, t_data_literal_noname,
		    strlen (t_data_literal_noname));
  cdk_stream_close (s);
  
  err = cdk_handle_new (&hd);
  if (err)
    goto fail;
  cdk_handle_control (hd, CDK_CTLF_SET, CDK_CTL_OVERWRITE, 1);
  
  /* If we do not provide an output file name for this function
     the literal filter would strip the file and remove absolute
     path names from it. Then the output would be created in the
     current directory which does not work for the test environment. */
  strcpy (outname, make_tempname ());
  err = cdk_file_decrypt (hd, inname, outname);
  cdk_handle_free (hd);
  if (err)
    goto fail;
  
  if (stat (outname, &stbuf) || stbuf.st_size != 1)
    err = CDK_Inv_Value;
  
  fail:
  unlink (inname);
  unlink (outname);
  return err;
}

  
/* Test to make sure that no illegal packet composition will
   be parsed with no error. */
static cdk_error_t test_sym_illegal_transform (void)
{
  cdk_ctx_t hd;
  cdk_error_t err;
  unsigned char *outbuf = NULL;
  size_t outsize;
  
  err = cdk_handle_new (&hd);
  if (err)
    return err;
  cdk_handle_set_passphrase_cb (hd, passphrase_cb, &files[0]);
  
  err = cdk_data_transform (hd, CDK_CRYPTYPE_DECRYPT, NULL, NULL,
			    t_data_literal_2, strlen (t_data_literal_2),
			    &outbuf, &outsize, 0);
  cdk_handle_free (hd);
  cdk_free (outbuf);
  
  /* We expect (!) a CDK_Inv_Packet here, other return codes indicate
     an error in the proc packet logic. */
  if (!err || err != CDK_Inv_Packet || outsize > 0)
    return CDK_Inv_Mode;
  
  return 0;
}


/* Test symmetric encryption. */
static cdk_error_t test_sym_transform (void)
{
  cdk_ctx_t hd;  
  cdk_error_t err;
  unsigned char *outbuf;
  size_t outsize;
  
  err = cdk_handle_new (&hd);
  if (err)
    return err;
  cdk_handle_set_passphrase_cb (hd, passphrase_cb, &files[0]);
  cdk_handle_set_armor (hd, 1);
  cdk_handle_set_cipher (hd, CDK_CIPHER_AES256);
  cdk_handle_set_s2k (hd, CDK_S2K_SALTED, CDK_MD_SHA512);
  
  err = cdk_data_transform (hd, CDK_CRYPTYPE_ENCRYPT,
			    NULL, NULL, t_data_plain, strlen (t_data_plain),
			    &outbuf, &outsize, 0);
  if (!err)
    {
      outbuf[outsize-1] = 0;
      if (!strstr ((char*)outbuf, "BEGIN PGP MESSAGE") || 
	  !strstr ((char*)outbuf, "END PGP MESSAGE"))
	err = CDK_Inv_Value;
      cdk_free (outbuf);
    }  
  
  cdk_handle_free (hd);
  return err;
}


static void test_decr_files (void)
{
  cdk_error_t err;
  int i;
  
  for (i=0; files[i].in_file != NULL; i++)
    {
      err = test_decr_one_file (&files[i]);
      if (err)
	{
	  err_cnt++;
	  fprintf (stderr, "%s:%d %s: %s FAILED\n", __FILE__, __LINE__,
		   files[i].in_file, cdk_strerror (err));
	}
      
    }
  
}


static const char *t_data_enc = 
  "-----BEGIN PGP MESSAGE-----\n"
  "\n"
  "hJgDeme3mVNMJv8BBGClKuovJ5DGoVnmY9T2Gc8WTlWhpIaopywxs+guDUtKlcic\n"
  "F+cdn3Ezcw1BbNG8oXSaT16MiSfUFd+CBy2zKA9NPyadBWpCIUNaLRSVOnzHo1Aw\n"
  "Ioj7mepSQtqTckzWkKoPt8Tux1kjz0k52T2oHFt/2Ppavste1W3QXp2/mLy+GuZt\n"
  "ZVyiXjKvfF5UYtJeAYK1fvYBuYeptpW7B/ie4IDk4F388oJxcoDW/YlAXSYf0NZm\n"
  "DqzgrUbeorVzBzreTDg/DeC15QtBMHRzJ8uzz1T2FtvXZvsQklUXcTHI5CQsEBrR\n"
  "2U4bx3m6AN0GgA==\n"
  "=DOg0\n"
  "-----END PGP MESSAGE-----\n";

static cdk_error_t
test_trans_one_encrypt (struct encrypt_test_s *one)
{
  cdk_ctx_t ctx;
  cdk_keydb_hd_t db;
  cdk_strlist_t recip;
  cdk_error_t err;
  size_t outsize;
  unsigned char *outbuf = NULL;
  
  err = cdk_handle_new (&ctx);
  if (err)
    return err;
  
  cdk_handle_control (ctx, CDK_CTLF_SET, CDK_CTL_ARMOR, 1);
  
  err = cdk_keydb_new_from_file (&db, 0, make_filename (one->keyfile));
  if (err)
    {
      cdk_handle_free (ctx);
      return err;
    }
  
  cdk_handle_set_keydb (ctx, db);
  
  recip = NULL;
  cdk_strlist_add (&recip, one->username);
  
  err = cdk_data_transform (ctx, CDK_CRYPTYPE_ENCRYPT, NULL, recip,
			    t_data_plain, strlen (t_data_plain),
			    &outbuf, &outsize, 0);
  if (!err)
    {
      if (outsize == 0 || outbuf == NULL)
	err = CDK_No_Data;
      else 
	{
	  outbuf[outsize-1] = 0;
	  if (!strstr ((char*)outbuf, "BEGIN PGP MESSAGE") ||
	      !strstr ((char*)outbuf, "END PGP MESSAGE"))
	    err = CDK_No_Data;
	}
    }
  
  /* Some tests expects an error and if this error occurred,
     we reset the return code because the test was successful. */
  if (err && err == one->expected)
    err = 0;
  
  if (outbuf != NULL)
    cdk_free (outbuf);
  cdk_handle_free (ctx);
  cdk_keydb_free (db);
  cdk_strlist_free (recip);
  return err;
}
  

/* Test to check that a single literal packet is also handled
   by the transform function. */
static cdk_error_t
test_trans_one_handle (void)
{
  cdk_ctx_t ctx;
  cdk_error_t err;
  size_t outsize;
  unsigned char *outbuf = NULL;
  
  err = cdk_handle_new (&ctx);
  if (err)
    return err;
  
  err = cdk_data_transform (ctx, CDK_CRYPTYPE_DECRYPT, NULL, NULL,
			    t_data_literal, strlen (t_data_literal),
			    &outbuf, &outsize, 0);
  cdk_handle_free (ctx);
  if (err)
    return err;
  
  if (!outbuf || !outsize || outsize != 5)
    err = CDK_Inv_Value;
  else
    {
      if (memcmp (outbuf, "test\n", outsize))
	err = CDK_Inv_Value;
    }  
  cdk_free (outbuf);
  return err;
}

static cdk_error_t
test_trans_one_decrypt (void)
{
  cdk_ctx_t ctx;
  cdk_keydb_hd_t db;
  cdk_error_t err;
  size_t outsize;
  unsigned char *outbuf = NULL;
  
  err = cdk_handle_new (&ctx);
  if (err)
    return err;
  
  err = cdk_keydb_new_from_file (&db, 1, make_filename ("sec.gpg"));
  if (err)
    {
      cdk_handle_free (ctx);
      return err;
    }
  
  cdk_handle_set_keydb (ctx, db);

  err = cdk_data_transform (ctx, CDK_CRYPTYPE_DECRYPT, NULL, NULL,
			    t_data_enc, strlen (t_data_enc),
			    &outbuf, &outsize, 0);
  if (!err)
    {
      if (!outbuf || !outsize)
	err = CDK_Inv_Value;
      else if (memcmp (outbuf, t_data_plain, strlen (t_data_plain)))
	err = CDK_Chksum_Error;
    }  
  
  if (outbuf != NULL)
    cdk_free (outbuf);
  cdk_handle_free (ctx);
  cdk_keydb_free (db);
  return err;
}


void test_transform_encrypt (void)
{
  cdk_error_t err;
  size_t i;
  
  for (i=0; test_encr[i].username != NULL; i++)
    {
      err = test_trans_one_encrypt (&test_encr[i]);
      if (err)
	{
	  fprintf (stderr, "%s:%d transform encrypt FAILED\n", 
		   __FILE__, __LINE__);
	  err_cnt++;
	}
      
    }
  
  err = test_sym_transform ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s:%d transform sym FAILED\n",
	       __FILE__, __LINE__);
    }
  
  err = tst_encr_all_recip_file ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s: %d all recipient FAILED\n",
	       __FILE__, __LINE__);
    }  
}
  

void test_transform_decrypt (void)
{
  cdk_error_t err;

  err = test_trans_one_decrypt ();
  if (err)
    {
      fprintf (stderr, "%s:%d decrypt FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_trans_one_handle ();
  if (err)
    {
      fprintf (stderr, "%s: %d handle FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_sym_illegal_transform ();
  if (err)
    {
      fprintf (stderr, "%s: %d illegal FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_lit_no_name ();
  if (err)
    {
      fprintf (stderr, "%s: %d no name test FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }  
}

static cdk_error_t test_partial_mode (void)
{
  cdk_ctx_t ctx;
  cdk_stream_t in, out;
  cdk_error_t err;
  char *buf, inname[256], outname[256];
  size_t buflen = 3*4096;

  err = cdk_handle_new (&ctx);
  if (err)
    return err;
  /*cdk_handle_set_cipher (ctx, CDK_CIPHER_CAST5);
  cdk_handle_set_s2k (ctx, CDK_S2K_SALTED, CDK_MD_SHA1);*/
  cdk_handle_set_compress (ctx, 0, 0);
  cdk_handle_set_blockmode (ctx, 1);
  cdk_handle_set_passphrase_cb (ctx, passphrase_cb, &files[0]);
  
  strcpy (inname, make_tempname ());
  err = cdk_stream_create (inname, &in);
  if (err)
    {
      cdk_handle_free (ctx);
      return err;
    }
  buf = cdk_malloc (buflen);
  memset (buf, 'A', buflen);
  cdk_stream_write (in, buf, buflen);
  cdk_stream_close (in);
  cdk_free (buf);
  
  strcpy (outname, make_tempname ());
  err = cdk_stream_open (inname, &in);
  if (!err)  
    err = cdk_stream_new (outname, &out);
  if (!err)
    err = cdk_stream_encrypt (ctx, NULL, in, out);
  
  cdk_stream_close (in);
  cdk_stream_close (out);
  cdk_handle_free (ctx);
  unlink (inname);
  if (!err)
    unlink (outname);
  return err;
}


static void test_misc_functions (void)
{
  cdk_error_t err;
  
  err = test_partial_mode ();
  if (err)
    {
      fprintf (stderr, "%s: %d partial mode FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    } 
}


int main (int argc, char **argv)
{
  cdk_lib_startup ();
  test_decr_files ();
  test_transform_decrypt ();
  test_transform_encrypt ();
  test_misc_functions ();
  cdk_lib_shutdown ();
  return err_cnt;
}
