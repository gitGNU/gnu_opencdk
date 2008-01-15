/* encrypt.c - functions related to en- and decryption
 *       Copyright (C) 2002, 2003, 2007 Timo Schulz
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
#include <stdarg.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"
#include "stream.h"


/* Write a marker packet to the output stream. */
static void
write_marker_packet (cdk_stream_t out)
{
  byte buf[5];
  
  buf[0] = (0x80 | (10<<2));
  buf[1] = 3;
  buf[2] = 0x50;
  buf[3] = 0x47;
  buf[4] = 0x50;
  cdk_stream_write (out, buf, 5);
}


static cdk_error_t
sym_stream_encrypt (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out)
{
  cdk_packet_t pkt;
  cdk_pkt_symkey_enc_t enc;
  cdk_s2k_t s2k;
  char *pw;
  cdk_error_t rc;
  
  if (!hd || !inp || !out)
    return CDK_Inv_Value;
  
  pw = _cdk_passphrase_get (hd, "Enter Passphrase: ");
  if (!pw)
    return CDK_Inv_Mode;

  rc = cdk_s2k_new (&s2k, hd->_s2k.mode, hd->_s2k.digest_algo, NULL);
  if (rc)
    goto fail;
    
  cdk_dek_free (hd->dek);
  rc = cdk_dek_from_passphrase (&hd->dek, hd->cipher_algo, s2k, 1, pw);
  if (rc)
    goto fail;
  
  if (hd->opt.blockmode)
    _cdk_stream_set_blockmode (out, DEF_BLOCKSIZE);
  
  cdk_stream_enable_cache (out, 1);
  write_marker_packet (out);
  
  rc = cdk_pkt_alloc (&pkt, CDK_PKT_SYMKEY_ENC);
  if (rc)
    goto fail;

  enc = pkt->pkt.symkey_enc;
  enc->version = 4;
  enc->cipher_algo = hd->dek->algo;
  enc->s2k = s2k; /* s2k is freed in cdk_pkt_release() */
  pkt->pkttype = CDK_PKT_SYMKEY_ENC;
  pkt->pkt.symkey_enc = enc;
  rc = cdk_pkt_write (out, pkt);
  cdk_pkt_release (pkt);
  cdk_stream_enable_cache (out, 0);
  if (rc)
    goto fail;

  if (hd->opt.armor)
    cdk_stream_set_armor_flag (out, 0);
  cdk_stream_set_cipher_flag (out, hd->dek, hd->opt.mdc);
  if (hd->opt.compress)
    cdk_stream_set_compress_flag (out, hd->compress.algo,
				  hd->compress.level);
  cdk_stream_set_literal_flag (out, 0, _cdk_stream_get_fname (inp));
  rc = cdk_stream_kick_off (inp, out);
  
  fail:
  if (pw)
    {
      wipemem (pw, strlen (pw));
      cdk_free (pw);
    }  
  return rc;
}


/**
 * cdk_stream_encrypt: Encrypt the given input stream.
 * @hd: Context handle for options
 * @remusr: List of recipients
 * @inp: Input stream handle
 * @out: Output stream handle
 *
 * If remusr is NULL, then symmetric encryption is used. Via the
 * handle the caller can set or unset multiple options.
 **/
cdk_error_t
cdk_stream_encrypt (cdk_ctx_t hd, cdk_strlist_t remusr,
                    cdk_stream_t inp, cdk_stream_t out)
{
  cdk_keylist_t pkl = NULL;
  int cipher_algo, compress_algo;
  cdk_error_t rc;

  if (!hd || !inp || !out)
    return CDK_Inv_Value;
  
  if (!remusr)
    return sym_stream_encrypt (hd, inp, out);
  
  rc = cdk_pklist_build (&pkl, hd->db.pub, remusr, CDK_KEY_USG_ENCR);
  if (rc)
    return rc;
  
  cipher_algo = cdk_pklist_select_algo (pkl, CDK_PREFTYPE_SYM);
  cdk_dek_free (hd->dek);
  rc = cdk_dek_new (&hd->dek);
  if (rc)
    return rc;
  
  rc = cdk_dek_set_cipher (hd->dek, cipher_algo);
  if (!rc)
    rc = cdk_dek_set_key (hd->dek, NULL, 0); /* create random key */
  if (rc) 
    {
      cdk_pklist_release (pkl);
      return rc;
    }
  compress_algo =  hd->compress.algo? hd->compress.algo : CDK_COMPRESS_ZIP;

  cdk_dek_set_mdc_flag (hd->dek, cdk_pklist_use_mdc (pkl));

  if (hd->opt.blockmode)
    _cdk_stream_set_blockmode (out, DEF_BLOCKSIZE);
  
  cdk_stream_enable_cache (out, 1);
  write_marker_packet (out);
  
  rc = cdk_pklist_encrypt (pkl, hd->dek, out);
  cdk_pklist_release (pkl);
  cdk_stream_enable_cache (out, 0);
  if (rc)
    return rc;

  if (hd->opt.armor)
    cdk_stream_set_armor_flag (out, 0);
  cdk_stream_set_cipher_flag (out, hd->dek, 0);
  if (hd->opt.compress)
    cdk_stream_set_compress_flag (out, compress_algo, hd->compress.level);
  cdk_stream_set_literal_flag (out, 0, _cdk_stream_get_fname (inp));
  
  return cdk_stream_kick_off (inp, out);
}


/**
 * cdk_file_encrypt: Encrypt a file.
 * @hd: Context handle
 * @remusr: List of recipient
 * @file: Input file
 * @output: Output file
 *
 * Encrypt the given file and encrypt the session key with the
 * given recipient keys.
 **/
cdk_error_t
cdk_file_encrypt (cdk_ctx_t hd, cdk_strlist_t remusr,
                  const char *file, const char *output)
{
  cdk_stream_t inp = NULL, out = NULL;
  cdk_error_t rc;

  rc = _cdk_check_args (hd->opt.overwrite, file, output);
  if (rc)
    return rc;
  
  rc = cdk_stream_open (file, &inp);
  if (rc)
    return rc;
  
  rc = cdk_stream_new (output, &out);
  if (!rc)
    rc = cdk_stream_encrypt (hd, remusr, inp, out);
  
  cdk_stream_close (inp);
  cdk_stream_close (out);
  return rc;
}


static int
check_pubkey_enc_list (cdk_stream_t in, cdk_keydb_hd_t hd)
{
  cdk_packet_t pkt;
  u32 keyid[2];
  size_t n, nenc;
  
  if (!in)
    return CDK_Inv_Value;
  
  /* If the user did not supply a keydb handle, we assume
     symmetric encryption is used and no check is needed. */
  if (!hd)
    return 0;

  n = nenc = 0;
  cdk_pkt_new (&pkt);
  while (!cdk_pkt_read (in, pkt)) 
    {      
      if (pkt->pkttype != CDK_PKT_PUBKEY_ENC)
	{
	  cdk_pkt_free (pkt);
	  break;
	}
      keyid[0] = pkt->pkt.pubkey_enc->keyid[0];
      keyid[1] = pkt->pkt.pubkey_enc->keyid[1];
      cdk_pkt_free (pkt);
      nenc++;
      if (!cdk_keydb_check_sk (hd, keyid))
	n++;
  }
  cdk_pkt_release (pkt);
  cdk_stream_seek (in, 0);
  if (!nenc)
    return 0;
  _cdk_log_debug ("found %d secret keys\n", n);
  return n > 0? 0 : CDK_Error_No_Key;
}


/**
 * cdk_file_decrypt:
 * @hd: Handle.
 * @file: Name of the file to decrypt.
 * @output: Output filename.
 *
 * Decrypt a file. When the operation was successful, hd can contain 
 * information about the signature (when present) and more.
 **/
cdk_error_t
cdk_file_decrypt (cdk_ctx_t hd, const char *file, const char *output)
{
  cdk_stream_t inp;
  cdk_error_t rc;

  if (!file)
    return CDK_Inv_Value;
  
  if (file && output)
    {      
      rc = _cdk_check_args (hd->opt.overwrite, file, output);
      if (rc)
	return rc;
    }  
  
  rc = cdk_stream_open (file, &inp);
  if (rc)
    return rc;
  
  if (cdk_armor_filter_use (inp))
    cdk_stream_set_armor_flag (inp, 0);
  
  rc = check_pubkey_enc_list (inp, hd->db.sec);
  if (!rc)
    rc = _cdk_proc_packets (hd, inp, NULL, output, NULL, NULL);
  
  cdk_stream_close (inp);
  return rc;
}


cdk_error_t
cdk_stream_decrypt (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out)
{
  cdk_error_t rc;

  if (cdk_armor_filter_use (inp))
    cdk_stream_set_armor_flag (inp, 0);

  rc = check_pubkey_enc_list (inp, hd->db.sec);
  if (!rc)
    rc = _cdk_proc_packets (hd, inp, NULL, NULL, out, NULL);
  return rc;
}


/**
 * cdk_data_transform:
 * @hd: session handle
 * @mode: crypto mode
 * @locusr: local user list (sign mode only)
 * @remusr: remote users 'recipients'
 * @inbuf: input buffer with data
 * @insize: length of data in bytes
 * @outbuf: pointer to the output data (will be allocated)
 * @outsize: size of the new data in bytes
 * @modval: value for the modus (for example sign mode)
 *
 * This function transforms data into the given openpgp mode. It works
 * exactly like the cdk_file_xxx functions with the exception that it can
 * be used with memory and not with streams or files.
 **/
cdk_error_t
cdk_data_transform (cdk_ctx_t hd, enum cdk_crypto_mode_t mode,
                    cdk_strlist_t locusr, cdk_strlist_t remusr,
                    const void *inbuf, size_t insize,
                    byte **outbuf, size_t *outsize,
                    int modval)
{
  cdk_stream_t inp, out;
  cdk_keydb_hd_t db;
  cdk_kbnode_t knode = NULL;
  cdk_error_t rc;
  
  if (!hd)
    return CDK_Inv_Value;
  if (!mode)
    return 0;
  
  /* In the signing mode we need at least a local user. */
  if (mode == CDK_CRYPTYPE_SIGN && !locusr)
    return CDK_Inv_Value;
  
  if (!inbuf || !insize || !outbuf)
    return CDK_Inv_Value;
  
  /* Reset output buffers. */
  *outbuf = NULL;
  *outsize = 0;
  
  rc = cdk_stream_tmp_from_mem (inbuf, insize, &inp);
  if (rc)
    return rc;
  rc = cdk_stream_tmp_new (&out);
  if (rc) 
    {
      cdk_stream_close (inp);
      return rc;
    }

  cdk_stream_tmp_set_mode (inp, 0);
  cdk_stream_tmp_set_mode (out, 1);

  switch (mode) 
    {
    case CDK_CRYPTYPE_ENCRYPT:
      rc = cdk_stream_encrypt (hd, remusr, inp, out);
      break;
      
    case CDK_CRYPTYPE_DECRYPT:
      rc = cdk_stream_decrypt (hd, inp, out);
      break;
      
    case CDK_CRYPTYPE_SIGN:
      rc = cdk_stream_sign (hd, inp, out, locusr, remusr, 0, modval);
      break;
      
    case CDK_CRYPTYPE_VERIFY:
      /* It is not possible to check detached signatures. */
      rc = cdk_stream_verify (hd, inp, NULL, out);
      break;
      
    case CDK_CRYPTYPE_EXPORT:
      if (cdk_handle_control (hd, CDK_CTLF_GET, CDK_CTL_ARMOR))
	cdk_stream_set_armor_flag (out, CDK_ARMOR_PUBKEY);
      db = cdk_handle_get_keydb (hd, CDK_DBTYPE_PK_KEYRING);
      rc = cdk_keydb_export (db, out, remusr);
      break;

    case CDK_CRYPTYPE_IMPORT:
      if (cdk_armor_filter_use (inp))
	cdk_stream_set_armor_flag (inp, 0);
      rc = cdk_keydb_get_keyblock (inp, &knode);
      if (knode) 
	{
	  db = cdk_handle_get_keydb (hd, CDK_DBTYPE_PK_KEYRING);
	  rc = cdk_keydb_import (db, knode);
	  if (!rc)
	    {
	      *outbuf = NULL;
	      *outsize = 0;
	    }
	  cdk_kbnode_release (knode);
	}
      break;
      
    default:
      _cdk_log_debug ("transform: invalid mode %d\n", mode);
      rc = CDK_Inv_Mode;
      break;
    }
  
  cdk_stream_close (inp);
  if (rc)
    {
      cdk_stream_close (out);
      return rc;
    } 
  
  if (mode != CDK_CRYPTYPE_VERIFY)
    {
      cdk_stream_tmp_set_mode (out, 0);
      rc = cdk_stream_mmap (out, outbuf, outsize);
  }
  else if (mode == CDK_CRYPTYPE_VERIFY)
    {
      /* The user can use cdk_handle_verify_get_result () to
         retrieve information about the signature and its status. */
      *outbuf = NULL;
      *outsize = 0;
    }
  
  cdk_stream_close (out);
  return rc;
}
