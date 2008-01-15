/* t-misc.c: regression tests for misc interfaces.
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


#include "opencdk.h"
#include "t-support.h"


static int err_cnt = 0;

/* WARNING: Because key generation is a lengthy process, this test suite
   should NOT be used in the autoconf environment because it takes too long. 
 */
cdk_error_t test_keygen (void)
{
  cdk_error_t err;
  cdk_keygen_ctx_t kg;
  char outsec[256], outpub[256];
  
  err = cdk_keygen_new (&kg);
  if (err)
    return err;

  strcpy (outsec, make_tempname ());
  strcpy (outpub, make_tempname ());
  cdk_keygen_set_passphrase (kg, "abc");
  cdk_keygen_set_name (kg, "OpenCDK Test Key <opencdk@my-cdk.de>");
  err = cdk_keygen_set_algo_info (kg, 0, CDK_KEY_USG_SIGN, CDK_PK_RSA, 1024);
  if (!err)
    err = cdk_keygen_set_algo_info (kg, 1, CDK_KEY_USG_ENCR,
				    CDK_PK_RSA, 1024);
  if (!err)
    err = cdk_keygen_start (kg);
  if (!err)
    err = cdk_keygen_save (kg, outpub, outsec);
  
  cdk_keygen_free (kg);
  unlink (outpub);
  unlink (outsec);
  return err;
}


cdk_error_t test_keyserver (void)
{
  cdk_kbnode_t key =NULL, n;
  cdk_packet_t pkt;
  cdk_error_t err;
  unsigned char keyid[4];
  unsigned int kid[2];
  
  keyid[0] = 0xE2;
  keyid[1] = 0x1C;
  keyid[2] = 0xCB;
  keyid[3] = 0xFE;

  err = cdk_keyserver_recv_key ("http://subkeys.pgp.net", 11371, keyid,
				CDK_DBSEARCH_SHORT_KEYID, &key);
  if (err)
    return err;
  cdk_kbnode_release (key);
  
  err = cdk_keyserver_recv_key ("hkp://subkeys.pgp.net", 11371, keyid,
				CDK_DBSEARCH_SHORT_KEYID, &key);
  if (err)
    return err;
  cdk_kbnode_release (key);  
  
  err = cdk_keyserver_recv_key ("subkeys.pgp.net", 11371, keyid,
				CDK_DBSEARCH_SHORT_KEYID, &key);
  if (err)
    return err;
  
  n = cdk_kbnode_find (key, CDK_PKT_PUBLIC_KEY);
  if (!n)
    {
      cdk_kbnode_release (key);
      return CDK_Inv_Value;
    }  

  pkt = cdk_kbnode_get_packet (n);
  cdk_pk_get_keyid (pkt->pkt.public_key, kid);
  if (kid[1] != 0xE21CCBFE)
    {
      cdk_kbnode_release (key);
      return CDK_Inv_Value;
    }
  
  n = cdk_kbnode_find (key, CDK_PKT_USER_ID);
  if (!n)
    {
      cdk_kbnode_release (key);
      return CDK_Inv_Value;
    } 

  cdk_kbnode_release (key);
  return err;
}

cdk_error_t test_armor_buffer (void)
{
  cdk_error_t err;
  cdk_stream_t in;
  size_t nout, calc_out;
  unsigned char buf[1024];
  char outbuf[4096];
  int n;
  
  err = cdk_stream_open (make_filename ("newkey.gpg"), &in);
  if (err)
    return err;
  
  n = cdk_stream_read (in, buf, 1024);
  if (n == -1 || !n)
    {
      cdk_stream_close (in);
      return CDK_File_Error;
    }    
  cdk_stream_close (in);
  
  cdk_armor_encode_buffer (buf, n, NULL, 0, &calc_out, CDK_ARMOR_PUBKEY);
  
  err = cdk_armor_encode_buffer (buf, n, outbuf, 4096,
				 &nout, CDK_ARMOR_PUBKEY);
  if (err)
    return err;
  if ((calc_out - nout) > 100)
    return CDK_Inv_Value;
  return 0;
}


/* Test that all public key algorithms return the correct
   amount of MPI parts. */
cdk_error_t test_pk_algorithms (void)
{
  int algos[] = {CDK_PK_RSA, CDK_PK_DSA, CDK_PK_ELG_E};
  size_t n = 3;
  
  while (n-- > 0)
    {
      if (cdk_pk_get_npkey (algos[n]) == 0 ||
	  cdk_pk_get_nskey (algos[n]) == 0)
	return CDK_Inv_Value;
    }
  return 0;
}

      
cdk_error_t test_malloc_funcs (void)
{
  cdk_set_malloc_hooks (gcry_malloc, gcry_malloc_secure, gcry_realloc,
			gcry_calloc, gcry_free);
  if (cdk_malloc_hook_initialized () != 1)
    return CDK_Inv_Value;
  return 0;
}


int main (int argc, char **argv)
{
  cdk_error_t err;

  /* For the tests, enable the quick random for speed-up and
     to avoid the program consumes real entropy. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  cdk_lib_startup ();
#ifdef WITH_INET_TESTS
  err = test_keyserver ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s:%d FAILED\n", __FILE__, __LINE__);
    }
#endif

  err = test_keygen ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s:%d genkey FAILED\n", __FILE__, __LINE__);
    }
  
  err = test_armor_buffer ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s:%d armor FAILED\n", __FILE__, __LINE__);
    }
  
  err = test_malloc_funcs ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s: %d malloc check FAILED\n", __FILE__, __LINE__);
    }
  
  err = test_pk_algorithms ();
  if (err)
    {
      err_cnt++;
      fprintf (stderr, "%s: %d pk algorithms FAILED\n", __FILE__, __LINE__);
    }  

  cdk_lib_shutdown ();
  return err_cnt;
}
