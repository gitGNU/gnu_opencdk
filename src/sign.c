/* sign.c - Signing routines
 *        Copyright (C) 2002, 2003 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * The OpenCDK library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "filters.h"
#include "stream.h"


static int file_clearsign (cdk_ctx_t, cdk_strlist_t,
                           const char *, const char *);
static int stream_clearsign (cdk_ctx_t, cdk_stream_t,
                             cdk_stream_t, cdk_strlist_t);


static void
calc_subpkt_size (cdk_pkt_signature_t sig)
{
  size_t nbytes;
  
  /* In the count mode no buffer is returned. */
  if (sig->hashed)
    {
      _cdk_subpkt_get_array (sig->hashed, 1, &nbytes);
      sig->hashed_size = nbytes;
    }
  
  if (sig->unhashed)
    {
      _cdk_subpkt_get_array (sig->unhashed, 1, &nbytes);
      sig->unhashed_size = nbytes;
    }
}


int
_cdk_sig_hash_for (cdk_pkt_pubkey_t pk)
{
  
  /* With the new DSA variants, we need to check the bits of
     the prime and the factor to decide what hash to use. */
  if (is_DSA (pk->pubkey_algo))
    {
      size_t pbits = gcry_mpi_get_nbits (pk->mpi[0]);
      size_t qbits = gcry_mpi_get_nbits (pk->mpi[1]);
      
      if (pbits <= 1024 && qbits <= 160)	
	return GCRY_MD_SHA1;
      if (pbits <= 2048 && qbits < 256)
	return GCRY_MD_SHA256/*224*/;
      else if (pbits <= 2048 && qbits > 224 && qbits <= 256)
	return GCRY_MD_SHA256;
      else
	return GCRY_MD_SHA384;
    }  
  else if (is_RSA (pk->pubkey_algo) && pk->version < 4)
    return GCRY_MD_MD5;
  return GCRY_MD_SHA256; /* default message digest */
}


cdk_error_t
_cdk_sig_create (cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig)
{
  cdk_subpkt_t n, node;
  byte buf[8];
  
  if( !sig )
    return CDK_Inv_Value;
  
  if (pk) 
    {
      if (!sig->version)
	sig->version = pk->version;
      sig->pubkey_algo = pk->pubkey_algo;
      sig->digest_algo = _cdk_sig_hash_for (pk);
      cdk_pk_get_keyid (pk, sig->keyid);
    }
  sig->timestamp = (u32)time (NULL);
  if (sig->version < 4)
    return 0;
  
  sig->hashed = sig->unhashed = NULL;
  
  _cdk_u32tobuf (sig->keyid[0], buf);
  _cdk_u32tobuf (sig->keyid[1], buf + 4);
  node = cdk_subpkt_new (8);
  if (!node)
    return CDK_Out_Of_Core;
  cdk_subpkt_init (node, CDK_SIGSUBPKT_ISSUER, buf, 8);
  sig->unhashed = node;
  
  _cdk_u32tobuf (sig->timestamp, buf);
  node = cdk_subpkt_new (4);
  if (!node)
    return CDK_Out_Of_Core;
  cdk_subpkt_init (node, CDK_SIGSUBPKT_SIG_CREATED, buf, 4);
  sig->hashed = node;
  
  if (sig->expiredate)
    {
      u32 u = sig->expiredate - sig->timestamp;
      _cdk_u32tobuf (u, buf);
      node = cdk_subpkt_new (4);
      if (!node)
	return CDK_Out_Of_Core;
      cdk_subpkt_init (node, CDK_SIGSUBPKT_SIG_EXPIRE, buf, 4);
      cdk_subpkt_add (sig->hashed, node);
    }
  
  if (pk->uid) 
    {
      char *p = cdk_utf8_encode (pk->uid->name);
      
      node = cdk_subpkt_new (strlen (p) + 1);
      if (!node)
	return CDK_Out_Of_Core;
      cdk_subpkt_init (node, CDK_SIGSUBPKT_SIGNERS_UID, p, strlen (p));
      cdk_subpkt_add (sig->hashed, node);
      cdk_free (p);
      
      if (pk->uid->selfsig)
	{
	  n = cdk_subpkt_find (pk->uid->selfsig->hashed,
			       CDK_SIGSUBPKT_PREF_KS);
	  if (n) 
	    {
	      node = cdk_subpkt_new (n->size+1);
	      if (!node)
		return CDK_Out_Of_Core;
	      cdk_subpkt_init (node, n->type, n->d, n->size);
	      cdk_subpkt_add (sig->hashed, node);
	    }
	}
    }
  
  calc_subpkt_size (sig);
  return 0;
}


cdk_error_t
_cdk_sig_complete (cdk_pkt_signature_t sig, cdk_pkt_seckey_t sk,
                   gcry_md_hd_t md)
{
  byte *mdbuf;
  
  if (!sig || !sk || !md)
    return CDK_Inv_Value;
  
  calc_subpkt_size (sig);
  _cdk_hash_sig_data (sig, md);
  gcry_md_final (md);
  mdbuf = gcry_md_read (md, sig->digest_algo);
  return cdk_pk_sign (sk, sig, mdbuf);
}


static cdk_error_t
write_literal (cdk_stream_t inp, cdk_stream_t out)
{
  cdk_packet_t pkt;
  cdk_pkt_literal_t pt;
  const char *s;
  int rc;
  
  if (!inp || !out)
    return CDK_Inv_Value;
  
  s = _cdk_stream_get_fname (inp);
  if (!s)
    s = "_CONSOLE";
  cdk_stream_seek (inp, 0);
  cdk_pkt_new (&pkt);
  pt = cdk_calloc (1, sizeof *pt + strlen (s) + 1);
  if (!pt)
    return CDK_Out_Of_Core;
  pt->len = cdk_stream_get_length (inp);
  pt->mode = 'b';
  pt->timestamp = (u32)time (NULL);
  pt->namelen = strlen (s);
  pt->buf = inp;
  strcpy (pt->name, s);
  pkt->pkttype = CDK_PKT_LITERAL;
  pkt->pkt.literal = pt;
  rc = cdk_pkt_write (out, pkt);
  cdk_pkt_release (pkt);
  return rc;
}


static cdk_error_t
write_pubkey_enc_list (cdk_ctx_t hd, cdk_stream_t out, cdk_strlist_t remusr)
{
  cdk_keylist_t pkl;
  cdk_error_t rc;
  
  if (!hd || !out)
    return CDK_Inv_Value;
  
  rc = cdk_pklist_build (&pkl, hd->db.pub, remusr, CDK_KEY_USG_ENCR);
  if (rc)
    return rc;
  
  cdk_dek_free (hd->dek);
  rc = cdk_dek_new (&hd->dek);
  if (rc)
    {
      cdk_pklist_release (pkl);
      return rc;
    } 

  rc = cdk_dek_set_cipher (hd->dek, cdk_pklist_select_algo (pkl, 1));
  if (!rc)
    rc = cdk_dek_set_key (hd->dek, NULL, 0); /* Randomize a session key */
  if (!rc)
    cdk_dek_set_mdc_flag (hd->dek, cdk_pklist_use_mdc (pkl));  
  if (!rc)
    rc = cdk_pklist_encrypt (pkl, hd->dek, out);

  cdk_pklist_release (pkl);
  return rc;
}


static int
sig_get_version (cdk_ctx_t hd, cdk_keylist_t kl)
{
  cdk_keylist_t l;
  
  /* We only use old signature if they are really needed. */
  for (l = kl; l; l = l->next)
    {    
      if (l->version == 3)
	return 3;
    }
  
  return 4;
}


/**
 * cdk_stream_sign:
 * @hd: session handle
 * @inp: input stream
 * @out: output stream
 * @locusr: local user list for signing
 * @remustr: remote user list for encrypting
 * @encryptflag: shall the output be encrypted? (1/0)
 * @sigmode: signature mode
 *
 * Sign the data from the STREAM @inp.
 **/
cdk_error_t
cdk_stream_sign (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out,
                 cdk_strlist_t locusr, cdk_strlist_t remusr,
                 int encryptflag, int sigmode)
{
  cdk_keylist_t list;
  cdk_pkt_seckey_t sk;
  md_filter_t *mfx;
  int sigver, digest_algo;
  int rc, detached = sigmode == CDK_SIGMODE_DETACHED;
  
  if (!hd)
    return CDK_Inv_Value;
  /* The encryptflag implies an embedded signature. */
  if (detached && encryptflag)
    return CDK_Inv_Mode;
  
  if (sigmode == CDK_SIGMODE_CLEAR)
    return stream_clearsign (hd, inp, out, locusr);
    
  rc = cdk_sklist_build (&list, hd->db.sec, hd, locusr, 1, CDK_KEY_USG_SIGN);
  if (rc)
    return rc;
  
  sk = list->key.sk;
  digest_algo = _cdk_sig_hash_for (sk->pk);
  /* We do not allow to force a digest when the DSA algorithm is used. */
  if (is_RSA (sk->pubkey_algo) && 
      cdk_handle_control (hd, CDK_CTLF_GET, CDK_CTL_FORCE_DIGEST))
    digest_algo = hd->digest_algo;
  
  if (hd->opt.armor)
    cdk_stream_set_armor_flag (out, detached? CDK_ARMOR_SIGNATURE : 0);
  
  if (encryptflag)
    {
      cdk_stream_enable_cache (out, 1);
      rc = write_pubkey_enc_list (hd, out, remusr);
      if (rc) 
	{	
	  cdk_sklist_release (list);
	  return rc;
	}
      cdk_stream_set_cipher_flag (out, hd->dek, hd->dek->use_mdc);
      cdk_stream_enable_cache (out, 0);
    }
  
  cdk_stream_set_hash_flag (inp, digest_algo);
  
  /* Kick off the filter */
  sigver = sig_get_version (hd, list);
  cdk_stream_read (inp, NULL, 0);
  mfx = _cdk_stream_get_opaque (inp, fHASH);
  if (!mfx || !mfx->md)
    {
      cdk_sklist_release (list);
      return rc;
    }
 
  if (sigver == 3)
    {
      rc = cdk_sklist_write (list, out, mfx->md, 0x00, 0x03);
      if (!rc && !detached)
	rc = write_literal (inp, out);
    }
  else 
    {
      if (!detached)
	{
	  rc = cdk_sklist_write_onepass (list, out, 0x00, digest_algo);
	  if (!rc)
	    rc = write_literal (inp, out);
	}
      if (!rc)
	rc = cdk_sklist_write (list, out, mfx->md, 0x00, 0x04);
    }
  
  cdk_sklist_release (list);
  return rc;
}


/**
 * cdk_file_sign:
 * @locusr: List of userid which should be used for signing
 * @remusr: If encrypt is valid, the list of recipients
 * @file: Name of the input file
 * @output: Name of the output file
 * @sigmode: Signature mode
 * @encrypt: enable sign and encrypt
 *
 * Sign a file.
 **/
cdk_error_t
cdk_file_sign (cdk_ctx_t hd, cdk_strlist_t locusr, cdk_strlist_t remusr,
               const char *file, const char *output,
               int sigmode, int encryptflag)
{
  cdk_stream_t inp = NULL, out = NULL;
  cdk_error_t rc;

  if (!file || !output)
    return CDK_Inv_Value;
  if (encryptflag && !remusr)
    return CDK_Inv_Mode;
  if ((sigmode != CDK_SIGMODE_NORMAL) && encryptflag)
    return CDK_Inv_Mode;
  if (!remusr && !locusr)
    return CDK_Inv_Value;
  if (sigmode == CDK_SIGMODE_CLEAR)
    return file_clearsign (hd, locusr, file, output);
  
  rc = cdk_stream_open (file, &inp);
  if (rc)
    return rc;
  
  if (hd->opt.armor || encryptflag)
    rc = cdk_stream_new (output, &out);
  else
    rc = cdk_stream_create (output, &out);
  if (rc)
    {
      cdk_stream_close (inp);
      return rc;
    }
  rc = cdk_stream_sign (hd, inp, out, locusr, remusr, encryptflag, sigmode);
  
  cdk_stream_close (inp);
  cdk_stream_close (out);
  return rc;
}


static void
put_hash_line (cdk_stream_t out, int digest_algo, int is_v4)
{
  const char *le, *s;
  
  le = _cdk_armor_get_lineend ();
  if (!is_v4) 
    {
      _cdk_stream_puts (out, le);
      return;
    }
  
  switch (digest_algo) 
    {
    case GCRY_MD_MD5    : s = "Hash: MD5"; break;
    case GCRY_MD_SHA1   : s = "Hash: SHA1"; break;
    case GCRY_MD_RMD160 : s = "Hash: RIPEMD160"; break;
    case GCRY_MD_SHA256 : s = "Hash: SHA256"; break;
    case GCRY_MD_SHA384 : s = "Hash: SHA384"; break;
    case GCRY_MD_SHA512 : s = "Hash: SHA512"; break;
    default             : s = "Hash: SHA1"; break;
    }
  _cdk_stream_puts (out, s);
  /* Because other platforms might have different line ending sequences,
     we do not hardcode them above. */
  _cdk_stream_puts (out, le);
  _cdk_stream_puts (out, le);
  
}


static int
stream_clearsign (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out,
                  cdk_strlist_t locusr)
{
  gcry_md_hd_t md = NULL;
  cdk_keylist_t list;
  cdk_stream_t tmp;
  cdk_pkt_seckey_t sk;
  char buf[1024+2];
  int digest_algo, sigver;
  int nread, le_one = 0;
  cdk_error_t rc;
  gcry_error_t err;
  
  rc = cdk_sklist_build (&list, hd->db.sec, hd, locusr, 1, CDK_KEY_USG_SIGN);
  if (rc)
    return rc;
  
  sk = list->key.sk;
  digest_algo = _cdk_sig_hash_for (sk->pk);
  err = gcry_md_open (&md, digest_algo, 0);
  if(rc)
    {
      cdk_sklist_release (list);
      return map_gcry_error (err);
    }
  
  _cdk_stream_puts (out, "-----BEGIN PGP SIGNED MESSAGE-----");
  _cdk_stream_puts (out, _cdk_armor_get_lineend ());
  put_hash_line (out, digest_algo, sk->version == 4);
  if (strlen (_cdk_armor_get_lineend ()) == 1)
    le_one = 1;
  
  while (!cdk_stream_eof (inp))
    {
      nread = _cdk_stream_gets (inp, buf, DIM (buf)-1);
      if (!nread || nread == -1)
	break;
      _cdk_trim_string (buf, 1);
      gcry_md_write (md, buf, strlen (buf));
      if (buf[0] == '-')
	{
	  memmove (&buf[2], buf, nread + 1);
	  buf[1] = ' ';
	}
      if (le_one) /* The line end has a length of one octet. */
	{
	  buf[strlen (buf) - 1] = '\0';
	  buf[strlen (buf) - 1] = '\n';
	}
      _cdk_stream_puts (out, buf);
    }
  _cdk_stream_puts (out, _cdk_armor_get_lineend ());
  rc = cdk_stream_tmp_new (&tmp);
  if (rc)
    goto leave;
  cdk_stream_tmp_set_mode (tmp, 1);
  cdk_stream_set_armor_flag (tmp, CDK_ARMOR_SIGNATURE);
  
  sigver = sig_get_version (hd, list);
  rc = cdk_sklist_write (list, tmp, md, 0x01, sigver);
  if (rc) 
    {
      cdk_stream_close (tmp);
      goto leave;
    }
  
  rc = cdk_stream_flush (tmp);
  if (rc)
    goto leave;
  
  while (!cdk_stream_eof (tmp))
    {
      nread = cdk_stream_read (tmp, buf, DIM (buf));
      if (!nread || nread == -1)
	break;
      cdk_stream_write (out, buf, nread);
    }
  cdk_stream_close (tmp);
  
  leave:
  gcry_md_close (md);
  cdk_sklist_release (list);
  return rc;
}


static cdk_error_t
file_clearsign (cdk_ctx_t hd, cdk_strlist_t locusr,
                const char * file, const char * output)
{
  cdk_stream_t inp = NULL, out = NULL;
  cdk_error_t rc;
  
  if (!locusr)
    return CDK_Inv_Value;
  
  rc = _cdk_check_args (hd->opt.overwrite, file, output);
  if (rc)
    return rc;

  rc = cdk_stream_open (file, &inp);
  if (!rc)
    rc = cdk_stream_create (output, &out);
  if (!rc)
    rc = stream_clearsign (hd, inp, out, locusr);
  
  cdk_stream_close (inp);
  cdk_stream_close (out);
  return rc;
}

