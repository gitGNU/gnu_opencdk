/* t-keydb.c - regression test for the key db functions.
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
#include <string.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "t-support.h"

static int err_cnt = 0;


static void fill_keyfpr (unsigned char *keyfpr)
{
  const char *s = "7BD4344BD9E79C83B064C975C5A6D35065BD473A";
  char buf[3];
  size_t i, pos = 0;
  
  for (i=0; i < strlen (s); i += 2)
    {
      buf[0] = s[i+0];
      buf[1] = s[i+1];
      buf[2] = 0;
      keyfpr[pos++] = strtoul (buf, NULL, 16);
    }
  
}


static const char *asc_key =
"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
"\n"
"mQGiBDxKxWwRBADnLna2Lu+po71ZQJMpJBgFDALXAp1sogZu/DTIYDhifGQ+saZS\n"
"p68dN89G/FBaweDGmbN4lbS8s+U1Qf/aR2bWFowriq/WqyJGbQbRgDTV2saY5pk7\n"
"pbNQ/4IuHNhwKnURTotzprCcs7k85E27UWybtflbtmYYhgKgoURyNsBljwCgj1te\n"
"eNhfeSzCBy+UdGRXJvtNk3MD/jV41onWYG6RGOn5pwQrljzyPz2PE3eic8Dwl02/\n"
"RLPKvL4U3WRBJVWGPjmpxidmLXesNmYq5El5LDJi0/EumDKnVlMJ1nugrk3yX17a\n"
"CTcFatW+ifQGnr1+x2zkMkQd9dUv/9BtOeX2HjaUe2mKd8tiq4HkpBIr+QUGcdmU\n"
"bIZeBADQYUN6lk3eMYgYwrJN4AjmAJa2DbimhLhag40Rn8kwMRiJrVejuSf0SPhO\n"
"slPGI+2nO0L/eLzmOmpTHXWmTOhUBROAjp9bEM4HXTQXuAEWSRixMdNUTIdlqOy5\n"
"lx9hoJ/HPVCYBhBrWXfSEcsOHQTQ7Za86Juuj3PYALBSE5y/jYhhBB8RAgAhBQI9\n"
"AjeQFwyAER11gQhbydn754sgeO1Ggcm/Pfm0AgcAAAoJEL1XLNzMwHw1jH0An3+h\n"
"2ZOIlNof+YsKL1kXrHJ1PhLbAKCAmPN5mIVnpxc9q06HVFrviH+qY7RJT3BlbkNE\n"
"SyB0ZXN0IGtleSAoT25seSBpbnRlbmRlZCBmb3IgdGVzdCBwdXJwb3NlcyEpIDxv\n"
"cGVuY2RrQGZvby1iYXIub3JnPohdBBMRAgAdBQsHCgMEAxUDAgMWAgECHgECF4AC\n"
"GQEFAjxKxW0ACgkQvVcs3MzAfDVrngCcD7nRHTS1y1VbzcqtNnuRW6tPGyUAnR+x\n"
"X2mQiQ7T6n31jqRvVITvybKc\n"
"=dDxB\n"
"-----END PGP PUBLIC KEY BLOCK-----\n";
  

cdk_error_t key_search_asc_data (void)
{
  cdk_keydb_hd_t db;
  cdk_error_t err;
  cdk_kbnode_t key;
  unsigned int keyid[2] = {0xBD572CDC, 0xCCC07C35};
  
  err = cdk_keydb_new_from_mem (&db, 0, asc_key, strlen (asc_key));
  if  (err)
    return err;
  
  err = cdk_keydb_get_bykeyid (db, keyid, &key);
  if (err)
    {
      cdk_keydb_free (db);
      return err;
    }
  
  cdk_keydb_free (db);
  
  if (!cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY))
    err = CDK_Inv_Value;
  
  cdk_kbnode_release (key);
  return err;
}

  
cdk_error_t key_search_asc_keyring (void)
{
  cdk_keydb_hd_t db;
  cdk_error_t err;
  cdk_kbnode_t key;
  unsigned int keyid[2] = {0xBD572CDC, 0xCCC07C35};
  
  err = cdk_keydb_new_from_file (&db, 0, make_filename ("pub-key.asc"));
  if (err)
    return err;
  
  err = cdk_keydb_get_bykeyid (db, keyid, &key);
  if (err)
    {
      cdk_keydb_free (db);
      return err;
    }

  if (!cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY))
    {
      cdk_kbnode_release (key);
      cdk_keydb_free (db);
      return CDK_Inv_Value;
    }
  cdk_kbnode_release (key);
  
  err = cdk_keydb_get_bypattern (db, "opencdk", &key);
  if (err)
    {
      cdk_keydb_free (db);
      return err;
    }
  
  if (!cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY))
    err = CDK_Inv_Value;
  
  cdk_kbnode_release (key);
  cdk_keydb_free (db);
  return err;
}
  

cdk_error_t key_db_stream (void)
{
  cdk_stream_t in;
  cdk_error_t err;
  cdk_keydb_hd_t db;
  cdk_kbnode_t key;
  unsigned keyid[2] = {0xBD572CDC, 0xCCC07C35};
  
  err = cdk_stream_open (make_filename ("pub.gpg"), &in);
  if (err)
    return err;
  
  err = cdk_keydb_new_from_stream (&db, 0, in);
  if (err)
    {
      cdk_stream_close (in);
      return err;
    }
  
  err = cdk_keydb_get_bykeyid (db, keyid, &key);
  cdk_keydb_free (db);
  cdk_stream_close (in);
  
  if (!cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY))
    err = CDK_Inv_Value;
  
  cdk_kbnode_release (key);
  return err;
}


cdk_error_t key_read_mpi (cdk_kbnode_t key)
{
  cdk_kbnode_t node_pk;
  cdk_packet_t pkt;
  cdk_pkt_pubkey_t pk;
  unsigned char buf[4096];
  size_t nbytes, i, nbits;
  
  node_pk = cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY);
  if (!node_pk)
    return CDK_Error_No_Key;
  pkt = cdk_kbnode_get_packet (node_pk);
  pk = pkt->pkt.public_key;
  for (i=0; i < cdk_pk_get_npkey (pk->pubkey_algo); i++)
    {
      gcry_mpi_t tmp;
      
      nbytes = 4096;
      cdk_pk_get_mpi (pk, i, buf, nbytes, &nbytes, &nbits);
      if (!nbytes || !nbits)
	return CDK_Inv_Value;
      if (gcry_mpi_scan (&tmp, GCRYMPI_FMT_PGP, buf, nbytes, &nbytes))
	return CDK_Inv_Value;
      gcry_mpi_release (tmp);
    }
  
  return 0;
}
  
  
cdk_error_t key_asc_tmp_read (void)
{
  cdk_kbnode_t key;
  cdk_stream_t inp;
  cdk_error_t rc;
  
  rc = cdk_stream_tmp_from_mem (asc_key, strlen (asc_key), &inp);
  if (rc)
    return rc;
  
  if (cdk_armor_filter_use (inp))
    rc = cdk_stream_set_armor_flag (inp, 0);
  if (!rc)
    rc = cdk_keydb_get_keyblock (inp, &key);
  if (!rc)
    {
      if (!cdk_kbnode_find_packet (key, CDK_PKT_PUBLIC_KEY))
	rc = CDK_Inv_Value;
    }
  if (!rc)
    rc = key_read_mpi (key);
  
  cdk_stream_close (inp);
  cdk_kbnode_release (key);
  return rc;
}

  
cdk_error_t key_search_mode (void)
{
  cdk_keydb_hd_t db;
  cdk_error_t err;
  cdk_kbnode_t key;
  unsigned int keyid[2];
  unsigned char keyfpr[20];
  
  err = cdk_keydb_new_from_file (&db, 0, make_filename ("pub.gpg"));
  if (err)
    return err;
  
  keyid[0] = 0xBB85E9F3;
  keyid[1] = 0x541D0CED;
  err = cdk_keydb_get_bykeyid (db, keyid, &key);
  if (err)
    goto fail;
  cdk_kbnode_release (key);
  
  err = cdk_keydb_get_bypattern (db, "opencdk", &key);
  if (err)
    goto fail;
  cdk_kbnode_release (key);
  
  fill_keyfpr (keyfpr);
  err = cdk_keydb_get_byfpr (db, keyfpr, &key);
  if (err)
    goto fail;
  cdk_kbnode_release (key);
  
  fail:
  cdk_keydb_free (db);
  return err;
}


cdk_error_t test_list_mode (void)
{
  static unsigned int kidlist[] = { /* all keys with a '<' in the user ID */
    0x65BD473A,
    0x541D0CED,
    0xCCC07C35,
    0xDC96D60C,
    0x653244D6,
    0x61F04784,
    0x4B11B25F,
    0
  };
  size_t n_keys = 7;
  cdk_keydb_hd_t db;
  cdk_error_t err;
  cdk_listkey_t ctx;
  cdk_kbnode_t key, n;
  size_t i;
  int found;
  
  err = cdk_keydb_new_from_file (&db, 0, make_filename ("pub.gpg"));
  if (err)
    return err;
  
  err = cdk_listkey_start (&ctx, db, "<", NULL);
  if (err)
    goto fail;
  
  while (!cdk_listkey_next (ctx, &key))
    {
      cdk_packet_t pkt;
      unsigned int kid[2];
      
      n = cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY);
      if (!n)
	{
	  cdk_kbnode_release (key);
	  err = CDK_Inv_Value;
	  goto fail;
	}     
      
      pkt = cdk_kbnode_get_packet (n);
      cdk_pk_get_keyid (pkt->pkt.public_key, kid);
      /* The the primary key ID must be in the kidlist
         which contains all primary key IDs. */
      found = 0;
      for (i=0; kidlist[i] != 0; i++)
	{
	  if (kid[1] == kidlist[i])
	    {
	      found = 1;
	      break;
	    }
	}     
      cdk_kbnode_release (key);
      if (!found)
	{
	  err = CDK_Inv_Value;
	  break;
	}     
      n_keys--;
    }  
  
  cdk_listkey_close (ctx);
  fail:
  cdk_keydb_free (db);
  if (n_keys != 0)
    return CDK_Inv_Value;
  return err;
}


cdk_error_t test_import (void)
{
  struct stat stbuf;
  cdk_stream_t in;
  cdk_keydb_hd_t db;
  cdk_kbnode_t key;
  cdk_error_t err;
  char keyname[256];
  
  strcpy (keyname, make_tempname ());
  err = cdk_stream_open (make_filename ("wkold.gpg"), &in);
  if (err)
    return err;
  
  err = cdk_keydb_get_keyblock (in, &key);
  if (err)
    {
      cdk_stream_close (in);
      return err;
    }
  
  err = cdk_keydb_new_from_file (&db, 0, keyname);
  if (err)
    {
      cdk_stream_close (in);
      cdk_kbnode_release (key);
      return err;
    }
  if (!err)
    err = cdk_keydb_import (db, key);
  
  cdk_keydb_free (db);
  cdk_kbnode_release (key);
  cdk_stream_close (in);
  
  if (!err)
    {
      if (stat (keyname, &stbuf) || stbuf.st_size < 1)
	err = CDK_Inv_Value;
    }
  unlink (keyname);
  return err;
}


cdk_error_t test_export (void)
{
  struct stat stbuf;
  cdk_strlist_t remusr = NULL;
  cdk_stream_t out;
  cdk_keydb_hd_t db;
  char outname[256];
  cdk_error_t err;
  
  strcpy (outname, make_tempname ());  
  err = cdk_keydb_new_from_file (&db, 0, make_filename ("pub.gpg"));
  if (err)
    return err;
  
  err = cdk_stream_create (outname, &out);
  if (err)
    {
      cdk_keydb_free (db);
      return err;
    }  
  
  cdk_strlist_add (&remusr, "uniform@example.net");  
  err = cdk_keydb_export (db, out, remusr);
  
  cdk_keydb_free (db);
  cdk_stream_close (out);
  cdk_strlist_free (remusr);
  if (!err && (stat (outname, &stbuf) || stbuf.st_size < 1))
    err = CDK_Inv_Value;
  unlink (outname);
  return err;
}


void keydb_tests (void)
{
  cdk_error_t err;

  err = key_search_mode ();
  if (err)
    {
      fprintf (stderr, "%s:%d keydb search FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_list_mode ();
  if (err)
    {
      fprintf (stderr, "%s: %d list FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = key_search_asc_keyring ();
  if (err)
    {
      fprintf (stderr, "%s: %d search asc file FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = key_search_asc_data ();
  if (err)
    {
      fprintf (stderr, "%s: %d search asc data FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = key_db_stream ();
  if (err)
    {
      fprintf (stderr, "%s: %d stream as db input FAILED\n", 
	       __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = key_asc_tmp_read ();
  if (err)
    {
      fprintf (stderr, "%s: %d asc tmp read FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_export ();
  if (err)
    {
      fprintf (stderr, "%s: %d key export FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  
  err = test_import ();
  if (err)
    {
      fprintf (stderr, "%s: %d key import FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }  
}

int main (int argc, char **argv)
{
  keydb_tests ();
  return err_cnt;
}
