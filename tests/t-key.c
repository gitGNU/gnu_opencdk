/* t-key.c: regression test for the public key API.
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
#include <assert.h>

#include "opencdk.h"
#include "t-support.h"

/* Global error counter. */
static int err_cnt = 0;

struct key_match_s
{
  const char *file;
  unsigned int low_keyid;
  const char *fpr;
};

/* List of files and the key ID of the primary file which is stored
   in the file. */
struct key_match_s tests[] =
{
  {"wkold.gpg",   0x0C9857A5, "629E97C0D555763B905AFAE9811C6409"},
  {"ts.gpg",      0xBF3DF9B4, "1D7581085BC9D9FBE78B2078ED4681C9BF3DF9B4"},
  {"pub.gpg",     0x65BD473A, "7BD4344BD9E79C83B064C975C5A6D35065BD473A"},
  {"pub-asc.gpg", 0xCCC07C35, "BE615E88D6CFF27225B8A2E7BD572CDCCCC07C35"},
  {"newkey.gpg",  0xDC96D60C, "E4C2361B83F029AF38C03AAA5F2B9469DC96D60C"},
  {NULL, 0}
};


static cdk_error_t test_photoid_key (void)
{
  cdk_error_t err;
  cdk_stream_t inp;
  cdk_kbnode_t key;
  unsigned char *buf;
  size_t buflen;
  
  err = cdk_stream_open (make_filename ("photo-key.gpg"), &inp);
  if (err)
    return err;
  
  err = cdk_keydb_get_keyblock (inp, &key);
  cdk_stream_close (inp);
  if (err)
    return err;
  
  err = cdk_kbnode_write_to_mem_alloc (key, &buf, &buflen);
  cdk_kbnode_release (key);

  cdk_free (buf);
  return err;
}


/* Very simple test to check the sexp representation of a key. */
static cdk_error_t test_sexp_key (cdk_kbnode_t key)
{
  cdk_packet_t pk;
  cdk_error_t err;
  char *sexp;
  size_t s_len;
  
  pk = cdk_kbnode_get_packet (key);
  err = cdk_pubkey_to_sexp (pk->pkt.public_key, &sexp, &s_len);
  if (err)
    return err;
  if (!s_len || !sexp)
    err = CDK_Inv_Value;
  cdk_free (sexp);
  return err;
}


static cdk_error_t test_check_subpkts (cdk_kbnode_t key)
{
  cdk_kbnode_t sig_node;
  cdk_subpkt_t n;
  cdk_packet_t pkt;
  cdk_pkt_signature_t sig;
  size_t type, len;
  int nsize;
  const unsigned char *p;
  
  pkt = cdk_kbnode_find_packet (key, CDK_PKT_PUBLIC_KEY);
  if (pkt->pkt.public_key->version < 4)
    return 0; /* version 3 key signature have no sub packets. */
  
  sig_node = cdk_kbnode_find (key, CDK_PKT_SIGNATURE);
  if (!sig_node)
    return CDK_Inv_Value;
  pkt = cdk_kbnode_get_packet (sig_node);
  sig = pkt->pkt.signature;
  
  n = cdk_subpkt_find (sig->unhashed, CDK_SIGSUBPKT_ISSUER);
  if (!n)
    return CDK_Inv_Value;
  p = cdk_subpkt_get_data (n, &type, &len);
  if (!p || type != CDK_SIGSUBPKT_ISSUER || len != 8)
    return CDK_Inv_Value;
  
  n = cdk_subpkt_find (sig->hashed, CDK_SIGSUBPKT_SIG_CREATED);
  if (!n)
    return CDK_Inv_Value;
  p = cdk_subpkt_get_data (n, &type, &len);
  if (!p || type != CDK_SIGSUBPKT_SIG_CREATED || len != 4)
    return CDK_Inv_Value;

  /* nsize is the amount of sub packets which must be present
     for the given signature class. */
  if (sig->sig_class > 0x10 && sig->sig_class < 0x13)
    nsize = 3;
  else
    nsize = 1;
  n = sig->hashed;
  for (;;)
    {      
      if (!cdk_subpkt_get_data (n, &type, &len))
	return CDK_Inv_Value;
      nsize--;
      n = cdk_subpkt_find_next (n, 0);
      if (!n)
	break;
    }  
  if (n > 0)
    return CDK_Inv_Value;
  
  return 0;
}

  
static cdk_error_t test_check_keysig (cdk_kbnode_t key)
{
  int status = 0;
  cdk_packet_t pk;
  cdk_error_t err;
  
  /* Test the sub packets first. */
  err = test_check_subpkts (key);
  if (err)
    return err;
  
  pk = cdk_kbnode_get_packet (key);
  
  /* Each key must at least contain one valid self signature. */
  err = cdk_pk_check_self_sig (key, &status);
  if (err || status != CDK_KEY_VALID)
    return CDK_Inv_Value;
  
  err = cdk_pk_check_sigs (key, NULL, &status);
  if (err)
    return err;
  /* The primary test keys are neither expired or revoked. */
  if (status & CDK_KEY_INVALID)
    return CDK_Inv_Value;
  return err;
}


/* Does a single test to see if the calculated key ID matches
   the saved key ID. The same for the fingerprint. */
static int test_one_keyid (struct key_match_s *one)
{
  cdk_stream_t in;
  cdk_kbnode_t key, pk;
  cdk_error_t err;
  cdk_packet_t pkt;
  char strfpr[41];
  unsigned int keyid, i;
  unsigned char fpr[20], chk_fpr[20];
  size_t n_fpr_out;
  
  err = cdk_stream_open (make_filename (one->file), &in);
  if (err)
    return err;
  
  if (cdk_armor_filter_use (in))
    cdk_stream_set_armor_flag (in, 0);
  
  err = cdk_keydb_get_keyblock (in, &key);
  if (err)
    return err;
  
  cdk_stream_close (in);
  pk = cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY);
  if (!pk)
    {
      cdk_kbnode_release (key);
      return CDK_Error_No_Key;
    }
  
  err = test_check_keysig (pk);
  if (err)
    {
      cdk_kbnode_release (pk);
      return err;
    }
  
  err = test_sexp_key (pk);
  if (err)
    {
      cdk_kbnode_release (pk);
      return err;
    }  

  pkt = cdk_kbnode_get_packet (pk);
  if (!pkt)
    {
      cdk_kbnode_release (pk);
      return CDK_Inv_Value;
    }

  keyid = cdk_pk_get_keyid (pkt->pkt.public_key, NULL);
  err = cdk_pk_get_fingerprint (pkt->pkt.public_key, fpr);
  if (!err)
    err = cdk_pk_to_fingerprint (pkt->pkt.public_key, chk_fpr, 20, &n_fpr_out);
  for (i=0; i < n_fpr_out; i++)
    sprintf (strfpr+2*i, "%02X", fpr[i]);
  cdk_kbnode_release (key);
  if (keyid != one->low_keyid)
    return 1; /* ERROR */
  if (strcmp (strfpr, one->fpr) || memcmp (chk_fpr, fpr, n_fpr_out))
    return 1;
  return 0;
}


static void test_keyid (void)
{
  int i;
  int err;
  
  for (i=0; tests[i].file != NULL; i++)
    {
      err = test_one_keyid (&tests[i]);
      if (err)
	{
	  printf ("%s:%d %s:%08lX: %s FAILED\n", __FILE__, __LINE__,
		  tests[i].file, (unsigned long)tests[i].low_keyid,
		  cdk_strerror (err));
	  err_cnt++;
	}      
    }
}


struct seckey_test_s
{
  const char *file;
  int version;
  int pubkey_algo;
  int nbits;
  unsigned short csum;
};

/* List of all secret keys with some of their packet values. */
struct seckey_test_s sec_tests[] =
{
  {"sec.gpg",    4, 17, 1024, 0x0ccf},
  {"newkey.sec", 4,  1, 2048, 0x3e6a},
  {NULL, 0, 0, 0}
};

static int test_one_secret_key (struct seckey_test_s *one)
{
  cdk_stream_t inp;
  cdk_error_t err;
  cdk_kbnode_t key;
  cdk_packet_t pkt;
  cdk_pubkey_t pk, cp_pk;
  
  err = cdk_stream_open (make_filename (one->file), &inp);
  if (err)
    return err;
  
  if (cdk_armor_filter_use (inp))
    cdk_stream_set_armor_flag (inp, 0);  
  
  err = cdk_keydb_get_keyblock (inp, &key);
  cdk_stream_close (inp);
  if (err)
    return err;
  
  pkt = cdk_kbnode_get_packet (key);
  if (pkt->pkttype != CDK_PKT_SECRET_KEY)
    {
      cdk_kbnode_release (key);
      return CDK_Inv_Value;
    }
  if (!pkt->pkt.secret_key->is_protected && 
      one->csum != pkt->pkt.secret_key->csum)
    {
      cdk_kbnode_release (key);
      return CDK_Inv_Value;
    }
  
  pk = pkt->pkt.secret_key->pk;
  if (pk->version != one->version || pk->pubkey_algo != one->pubkey_algo)
    err = CDK_Inv_Value;
  else if (gcry_mpi_get_nbits (pk->mpi[0]) != one->nbits)
    err = CDK_Inv_Value;
  else if (pk->timestamp == 0)
    err = CDK_Inv_Value;
  
  err = cdk_pk_from_secret_key (pkt->pkt.secret_key, &cp_pk);
  if (!err)
    {
      if (cp_pk->version != pk->version ||
	  cp_pk->pubkey_algo != pk->pubkey_algo)
	err = CDK_Inv_Value;
      cdk_pk_release (cp_pk);
    }  
  
  cdk_kbnode_release (key);
  return err;
}


static void test_secret_key (void)
{
  int i, err;
  
  for (i=0; sec_tests[i].file != NULL; i++)
    {
      err = test_one_secret_key (&sec_tests[i]);
      if (err)
	{
	  printf ("%s:%d %s: FAILED\n", __FILE__, __LINE__, sec_tests[i].file);
	  err_cnt++;
	}      
    }  
}


static cdk_error_t test_missing_key (void)
{
  cdk_stream_t in;
  cdk_error_t err;
  cdk_kbnode_t key;
  cdk_packet_t pk;
  cdk_keydb_hd_t db;
  unsigned char *buf;
  size_t buflen;
  int status = 0;
  
  err = cdk_stream_open (make_filename ("wkold.gpg"), &in);
  if (err)
    return err;
  err = cdk_stream_mmap (in, &buf, &buflen);
  cdk_stream_close (in);
  if (err)
    return err;
  err = cdk_kbnode_read_from_mem (&key, buf, buflen);
  cdk_free (buf);
  if (err)
    return err;
  pk = cdk_kbnode_get_packet (key);
  if (pk->pkttype != CDK_PKT_PUBLIC_KEY)
    {
      cdk_kbnode_release (key);
      return CDK_General_Error;
    }
  err = cdk_keydb_new_from_file (&db, 0, make_filename ("pub.gpg"));
  if (err)
    {
      cdk_kbnode_release (key);
      return CDK_General_Error;
    }  
  err = cdk_pk_check_sigs (key, db, &status);
  cdk_kbnode_release (key);
  cdk_keydb_free (db);
  if (status & CDK_KEY_INVALID)
    return CDK_General_Error;
  if (!(status & CDK_KEY_NOSIGNER))
    return CDK_General_Error;
  return err;
}

static cdk_error_t test_expired_key (void)
{
  cdk_stream_t in;
  cdk_error_t err;
  cdk_kbnode_t key;
  cdk_packet_t pk;
  unsigned char *buf;
  size_t buflen;
  int status = 0;
  
  err = cdk_stream_open (make_filename ("exp-key.gpg"), &in);
  if (err)
    return err;
  err = cdk_stream_mmap (in, &buf, &buflen);
  cdk_stream_close (in);
  if (err)
    return err;
  err = cdk_kbnode_read_from_mem (&key, buf, buflen);
  cdk_free (buf);
  if (err)
    return err;
  pk = cdk_kbnode_get_packet (key);
  if (pk->pkttype != CDK_PKT_PUBLIC_KEY ||
      pk->pkt.public_key->has_expired == 0)
    {
      cdk_kbnode_release (key);
      return CDK_General_Error;
    }
  err = cdk_pk_check_sigs (key, NULL, &status);
  cdk_kbnode_release (key);
  if (!(status & CDK_KEY_EXPIRED))
    return CDK_General_Error;
  if (status & CDK_KEY_INVALID)
    return CDK_General_Error;
  return err;
}


static cdk_error_t test_kbnode_read_write (const char *file)
{
  cdk_kbnode_t in_key, n;
  cdk_error_t err;
  cdk_stream_t in, out;
  unsigned char *buf;
  char outname[256];
  size_t buflen;
  
  err = cdk_stream_open (make_filename (file), &in);
  if (err)
    return err;
  
  err = cdk_stream_mmap (in, &buf, &buflen);
  cdk_stream_close (in);
  if (err)
    return err;
  
  in_key = NULL;
  err = cdk_kbnode_read_from_mem (&in_key, buf, buflen);
  cdk_free (buf);
  if (err)
    {
      cdk_kbnode_release (in_key);
      return err;
    }
  strcpy (outname, make_tempname ());
  n = cdk_kbnode_find (in_key, CDK_PKT_PUBLIC_KEY);
  if (!n)
    err = CDK_Error_No_Key;
  if (!err)
    err = cdk_kbnode_write_to_mem_alloc (in_key, &buf, &buflen);
  if (!err)
    err = cdk_stream_create (outname, &out);
  if (!err)
    {
      int nw = cdk_stream_write (out, buf, buflen);
      if (nw == 0 || nw == -1)
	err = CDK_File_Error;
      cdk_stream_close (out);
    }
  else
    fprintf (stderr, "kbnode read: %s\n", cdk_strerror (err));

  cdk_free (buf);
  cdk_kbnode_release (in_key);
  unlink (outname);
  return err;
}


void test_kbnode_funcs (void)
{
  cdk_error_t err;
  
  err = test_kbnode_read_write ("ts.gpg");
  err = 0;
  if (err)
    {
      fprintf (stderr, "%s:%d kbnode read FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_photoid_key ();
  if (err)
    {
      fprintf (stderr, "%s:%d photo-id key FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }  
}
      

void test_invalid_keys (void)
{
  
  cdk_error_t err;
  
  err = test_expired_key();
  if (err)
    {
      fprintf (stderr, "%s:%d expired key test FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  err = test_missing_key ();
  if (err)
    {
      fprintf (stderr, "%s:%d missing key test FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }  
}      
  

int main (int argc, char **argv)
{
  cdk_lib_startup ();
  test_secret_key ();
  test_keyid ();
  test_kbnode_funcs ();
  test_invalid_keys ();
  cdk_lib_shutdown ();
  return err_cnt;
}
