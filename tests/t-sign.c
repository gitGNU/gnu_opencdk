/* t-sign.c
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

#include "opencdk.h"
#include "t-support.h"


static int err_cnt = 0;

struct sig_test_s
{
  const char *sig_file;
  const char *data_file;
  const char *key_file;
  int is_detached;
};

/* Files with test data, if the second entry is not NULL
   the file contains a detached sig. */
struct sig_test_s c_files[] =
{
  {"plain-test.gpg", NULL, "pub.gpg", 0},
  {"plain-test-cs.asc", NULL, "pub.gpg", 0},
  {"plain-test.sig", "plain-test", "pub.gpg", 1},
  {NULL}
};     

static const char *plain_test = "hello, this is supposed to be signed.";

static cdk_error_t test_sample_out (void);


static cdk_error_t check_verify_result (cdk_ctx_t hd)
{
  cdk_verify_result_t res;
  
  res = cdk_handle_verify_get_result (hd);
  if (!res)
    return CDK_Inv_Value;
  
  if (res->sig_ver != 4 || res->sig_len < 1024 ||
      gcry_md_test_algo (res->digest_algo) ||
      gcry_pk_test_algo (res->pubkey_algo))
    return CDK_Inv_Value;
  
  if (res->keyid[0] == 0 || res->keyid[1] == 0)
    return CDK_Inv_Value;
  if (res->sig_status != CDK_SIGSTAT_GOOD)
    return CDK_Bad_Sig;
  
  return 0;
}

  
static cdk_error_t test_one_sig_file (struct sig_test_s *sig)
{
  cdk_ctx_t hd;
  cdk_keydb_hd_t db;
  cdk_error_t err;
  char output[256];
  char dat_file[256];
  
  err = cdk_handle_new (&hd);
  if (err)
    return err;
  
  err = cdk_keydb_new_from_file (&db, 0, make_filename (sig->key_file));
  if (err)
    {
      cdk_handle_free (hd);
      return err;
    }  
  
  cdk_handle_control (hd, CDK_CTLF_SET, CDK_CTL_OVERWRITE, 1);  
  cdk_handle_set_keydb (hd, db);
  strcpy (output, make_tempname ());
  if (!sig->is_detached)
    err = cdk_file_verify (hd, make_filename (sig->sig_file), NULL, output);
  else
    {
      cdk_stream_t tmp;
      
      strcpy (dat_file, make_tempname ());
      err = cdk_stream_create (dat_file, &tmp);
      if (!err)
	{
	  cdk_stream_write (tmp, plain_test, strlen (plain_test));
	  cdk_stream_close (tmp);
	  err = cdk_file_verify (hd, make_filename (sig->sig_file), 
				 dat_file, output);
	}
    }
  
  if (!err)
    err = check_verify_result (hd);

  cdk_keydb_free (db);
  cdk_handle_free (hd);
  unlink (output);
  if (sig->is_detached)
    unlink (dat_file);
  return err;
}

static void test_clearsig_files (void)
{
  cdk_error_t err;
  int i;
  
  err = test_sample_out ();
  if (err)
    {
      fprintf (stderr, "%s: %d sample data FAILED\n", __FILE__, __LINE__);
      err_cnt++;
      return;
    }
   
  for (i=0; c_files[i].sig_file != NULL; i++)
    {
      err = test_one_sig_file (&c_files[i]);
      if (err)
	{
	  fprintf (stderr, "%s:%d %s: FAILED\n", __FILE__, __LINE__,
		   c_files[i].sig_file);
	  err_cnt++;
	}     
    }  
}

static cdk_error_t test_sample_out (void)
{  
  cdk_stream_t out;
  cdk_error_t err;
  char outname[256];
  
  strcpy (outname, make_tempname ());
  err = cdk_stream_create (outname, &out);
  if (err)
    return err;
  cdk_stream_write (out, plain_test, strlen (plain_test));
  cdk_stream_close (out);
  unlink (outname);
  return 0;
}


static cdk_error_t test_sign_enc (void)
{
  cdk_ctx_t ctx;
  cdk_keydb_hd_t pub_db;
  cdk_keydb_hd_t sec_db;
  cdk_strlist_t rset, user;
  cdk_stream_t tmp;
  cdk_error_t err;
  char out[512], in[256];
  
  err = cdk_handle_new (&ctx);
  if (err)
    return err;
  
  err = cdk_keydb_new_from_file (&pub_db, 0, make_filename ("pub.gpg"));
  if (err)
    {
      cdk_handle_free (ctx);
      return err;
    }  
  cdk_handle_set_keydb (ctx, pub_db);
  
  err = cdk_keydb_new_from_file (&sec_db, 1, make_filename ("sec.gpg"));
  if (err)
    {
      cdk_keydb_free (pub_db);
      cdk_handle_free (ctx);
      return err;
    }
  cdk_handle_set_keydb (ctx, sec_db);
  
  rset = NULL; /* recipients */
  cdk_strlist_add (&rset, "opencdk");
  
  user = NULL; /* local user = signer */
  cdk_strlist_add (&user, "opencdk");  
  
  strcpy (in, make_tempname ());
  err = cdk_stream_create (in, &tmp);
  if (!err)
    {
      cdk_stream_write (tmp, plain_test, strlen (plain_test));
      cdk_stream_close (tmp);
      strcpy (out, make_tempname ());
      err = cdk_file_sign (ctx, user, rset, in, out, CDK_SIGMODE_NORMAL, 1);
    }
 
  cdk_keydb_free (pub_db);
  cdk_keydb_free (sec_db);
  cdk_handle_free (ctx);
  cdk_strlist_free (user);
  cdk_strlist_free (rset);
  unlink (out);
  unlink (in);
  return err;
}


static void test_sign_data (void)
{
  cdk_error_t err;
  
  err = test_sign_enc ();
  if (err)
    {
      fprintf (stderr, "%s:%d sign enc FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }  
}



int main (int argc, char **argv)
{
  cdk_lib_startup ();
  test_clearsig_files ();
  test_sign_data  ();
  cdk_lib_shutdown ();
  return err_cnt;
}
