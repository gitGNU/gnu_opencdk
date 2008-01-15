/* keylist.c
 *        Copyright (C) 2002, 2003, 2007 Timo Schulz
 *        Copyright (C) 1998-2002 Free Software Foundation, Inc.
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
# include <config.h>
#endif
#include <stdio.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"


/* Here we check if *all* keys have the MDC feature. Even if one
   key doesn't support it, it is not used. */
int
cdk_pklist_use_mdc (cdk_keylist_t pk_list)
{
  cdk_keylist_t pkr;
  int mdc = 0;
  
  if (!pk_list)
    return 0;
  
  for (pkr = pk_list; pkr; pkr = pkr->next)
    {
      if (pkr->key.pk->uid) /* selected by user ID */
	mdc = pkr->key.pk->uid->mdc_feature;
      if (!mdc)
	return 0;
  }
  
  return 1;
}


static int
check_algo (int preftype, int algo)
{
  if (preftype == CDK_PREFTYPE_SYM)
    return algo && !gcry_cipher_test_algo (algo);
  else if (preftype == CDK_PREFTYPE_HASH)
    return algo && !gcry_md_test_algo( algo );
  else if (preftype == CDK_PREFTYPE_ZIP)
    return !algo || algo == 1 || algo == 2 || algo == 3;
  else
    return 0;
}


/**
 * cdk_pklist_select_algo:
 * @pkl: the keylist
 * @preftype: preference type
 *
 * Select a symmetric cipher algorithm from a list of public keys.
 * This algorithm is present in all key preferences.
 **/
int
cdk_pklist_select_algo( cdk_keylist_t pkl, int preftype )
{
    const struct cdk_prefitem_s * prefs;
    cdk_keylist_t pkr;
    u32 bits[8];
    int compr_hack = 0, any = 0;
    int i = 0, j = 0;

    if (!pkl)
        return -1;

    memset (bits, ~0, 8 * sizeof *bits);
    for (pkr = pkl; pkr; pkr = pkr->next) {
        u32 mask[8];
        if (preftype == CDK_PREFTYPE_SYM) {
            memset (mask, 0, 8 * sizeof *mask);
            mask[0] |= (1 << 2); /*3DES is implicitly there for everyone else*/
	}
        if (pkr->key.pk->uid)
            prefs = pkr->key.pk->uid->prefs;
        else
            prefs = pkr->key.pk->prefs;      
        any = 0;
        for (i = 0; prefs && prefs[i].type; i++) {
            if (prefs[i].type == preftype) {
                mask[prefs[i].value / 32] |= 1 << (prefs[i].value % 32);
                any = 1;
	    }
	}
        if ((!prefs || !any) && preftype == CDK_PREFTYPE_ZIP) {
            mask[0] |= 3; /* asume no_compression and old pgp */
            compr_hack = 1;
	}
        for (i = 0; i < 8; i++)
            bits[i] &= mask[i];
        /* Usable algorithms are now in bits:
           We now use the last key from pkl to select the algorithm we want
           to use. There are no preferences for the last key, we select the one
           corresponding to first set bit. */
        i = -1;
        any = 0;
        for (j = 0; prefs && prefs[j].type; j++) {
            if (prefs[j].type == preftype) {
                if ((bits[prefs[j].value / 32] & (1 << (prefs[j].value % 32))))
		{
                    if (check_algo (preftype, prefs[j].value)) {
                        any = 1;
                        i = prefs[j].value;
                        break;
		    }
		}
	    }
	}
        if (!prefs || !any) {
            for (j = 0; j < 256; j++)
                if ((bits[j / 32] & (1 << (j % 32)))) {
                    if (check_algo (preftype, j)) {
                        i = j;
                        break;
                    }
                }
	}
        if (compr_hack && !i) {
            /* selected no compression, but we should check whether
               algorithm 1 is also available (the ordering is not relevant
               in this case). */
            if (bits[0] & (1 << 1))
                i = 1; /* yep; we can use compression algo 1 */
	}
    }
    _cdk_log_debug ("selected algo %d from prefs\n", i);
    return i;
}


static int
is_duplicated_entry (cdk_strlist_t list, cdk_strlist_t item)
{
  for (; list && list != item; list = list->next)
    {
      if (!strcmp (list->d, item->d))
	return 1;
    }
  
  return 0;
}


/**
 * cdk_pklist_release:
 * @pkl: the keylist
 *
 * Free the memory of the key list.
 **/
void
cdk_pklist_release (cdk_keylist_t pkl)
{
  cdk_keylist_t pkr;
  
  for (; pkl; pkl = pkr)
    {
      pkr = pkl->next;
      cdk_pk_release (pkl->key.pk);
      pkl->key.pk = NULL;
      cdk_free (pkl);
    }
}


/**
 * cdk_pklist_build:
 * @ret_pkl: the new keylist
 * @hd: the session handle
 * @remusr: the string list of the recipients
 * @usage: public key usage
 *
 * Create a public key list based on the recipient names in @remusr.
 **/
cdk_error_t
cdk_pklist_build (cdk_keylist_t * ret_pkl, cdk_keydb_hd_t db,
                  cdk_strlist_t remusr, int usage)
{
  cdk_keylist_t pk_list = NULL, r = NULL, l;
  cdk_pkt_pubkey_t pk = NULL;
  int rc = 0;
  
  if (!db)
    return CDK_Error_No_Keyring;
  
  for (; remusr; remusr = remusr->next)
    {
      rc = _cdk_keydb_get_pk_byusage (db, remusr->d, &pk, usage);
      if (rc)
	break;
      else 
	{
	  for (l = pk_list; l; l = l->next)
	    {
	      if (!_cdk_pubkey_compare (l->key.pk, pk))
		{
		  cdk_pk_release (pk);
		  pk = NULL;
		  continue; /* key already in list so skip it */
                }
            }
	  r = cdk_calloc (1, sizeof *r);
	  if (!r)
	    {
	      rc = CDK_Out_Of_Core;
	      break;
	    }
	  r->type = CDK_PKT_PUBLIC_KEY;
	  r->version = pk->version;
	  r->key.pk = pk;
	  r->next = pk_list;
	  pk_list = r;
	}
    }
  
  if (rc)
    {
      cdk_pklist_release (pk_list);
      pk_list = NULL;
    }
  
  *ret_pkl = pk_list;
  return rc;
}


/* Return 1 if at least one key in the list is an old v3 key. */
static int
use_rfc1991_format (cdk_keylist_t kl)
{
  cdk_keylist_t l;
  
  for (l = kl; l; l = l->next)
    {
      if (l->version == 3)
	return 1;
    }
  
  return 0;
}



/**
 * cdk_pklist_encrypt:
 * @pkl: the keylist
 * @dek: the data encryption key
 * @outp: the stream to write in the data
 *
 * Encrypt the session key with each key of the list and wrap it
 * into a PUBKEY_ENC packet and write it to @outp.
 */
cdk_error_t
cdk_pklist_encrypt (cdk_keylist_t pk_list, cdk_dek_t dek, cdk_stream_t outp)
{
  cdk_packet_t pkt;
  gcry_mpi_t frame;
  cdk_error_t rc;
  int use_rfc1991;
  
  if (!pk_list || !dek || !outp)
    return CDK_Inv_Value;
  
  if (pk_list->type != CDK_PKT_PUBLIC_KEY)
    return CDK_Inv_Mode;
  
  use_rfc1991 = use_rfc1991_format (pk_list);
  for (; pk_list; pk_list = pk_list->next)
    {
      cdk_pkt_pubkey_t pk = pk_list->key.pk;
      cdk_pkt_pubkey_enc_t enc;
      
      rc = cdk_pkt_alloc (&pkt, CDK_PKT_PUBKEY_ENC);
      if (rc)
	return rc;
      
      enc = pkt->pkt.pubkey_enc;
      enc->version = 3;
      enc->pubkey_algo = pk->pubkey_algo;
      cdk_pk_get_keyid (pk, enc->keyid);
      
      rc = cdk_dek_encode_pkcs1 (dek, cdk_pk_get_nbits (pk), &frame);
      if (!rc)
	rc = cdk_pk_encrypt (pk, enc, frame);
      if (!rc)
	{
	  pkt->old_ctb = use_rfc1991;
	  pkt->pkttype = CDK_PKT_PUBKEY_ENC;
	  rc = cdk_pkt_write (outp, pkt);
	}
      gcry_mpi_release (frame);
      cdk_pkt_release (pkt);
      if (rc)
	return rc;
    }
  return 0;
}


/**
 * cdk_sklist_release:
 * @skl: secret keylist
 *
 * Free the memory of the secret keylist.
 **/
void
cdk_sklist_release (cdk_keylist_t sk_list)
{
  cdk_keylist_t sk_rover = NULL;
  
  for (; sk_list; sk_list = sk_rover)
    {
      sk_rover = sk_list->next;
      cdk_sk_release (sk_list->key.sk);
      sk_list->key.sk = NULL;
      cdk_free (sk_list);
    }
}


/**
 * cdk_sklist_build:
 * @ret_skl: return the allocated sec key list.
 * @db: keydb handle
 * @hd: session handle
 * @locusr: local user list
 * @unlock: 1=unlock secret keys
 * @usage: secret key usage.
 * 
 **/
cdk_error_t
cdk_sklist_build (cdk_keylist_t *ret_skl, cdk_keydb_hd_t db, cdk_ctx_t hd,
                  cdk_strlist_t locusr, int unlock, unsigned int usage)
{
  cdk_keylist_t r = NULL, sk_list = NULL;
  cdk_pkt_seckey_t sk = NULL;
  cdk_error_t rc;

  if (!hd || !ret_skl )
    return CDK_Inv_Value;
  if (!db)
    return CDK_Error_No_Keyring;
  
  rc = 0;
  if (!locusr) /* Use the default secret key. */
    {
      rc = _cdk_keydb_get_sk_byusage (db, NULL, &sk, usage);
      if (rc) 
	{
	  cdk_sk_release (sk);
	  return rc;
	}
      if (unlock)
	{
	  rc = _cdk_sk_unprotect_auto (hd, sk);
	  if (rc)
	    return rc;
        }
      
      r = cdk_calloc (1, sizeof *r);
      if (!r)
	return CDK_Out_Of_Core;
      r->type = CDK_PKT_SECRET_KEY;
      r->version = sk->version;
      r->key.sk = sk;
      r->next = sk_list;
      sk_list = r;
    }
  else 
    {
      cdk_strlist_t locusr_orig = locusr;

      for (; locusr; locusr = locusr->next) 
	{
	  if (is_duplicated_entry (locusr_orig, locusr))
	    continue;
	  rc = _cdk_keydb_get_sk_byusage (db, locusr->d, &sk, usage);
	  if (rc) 
	    {
	      cdk_sk_release (sk);
	      sk = NULL;
	    }
	  else 
	    {
	      if (unlock)
		{
		  rc = _cdk_sk_unprotect_auto (hd, sk);
		  if (rc)
		    break;
		}
	      r = cdk_calloc (1, sizeof *r);
	      if (!r)
		return CDK_Out_Of_Core;
	      r->type = CDK_PKT_SECRET_KEY;
	      r->version = sk->version;
	      r->key.sk = sk;
	      r->next = sk_list;
	      sk_list = r;
	    }
	}
    }
  
  if (rc)
    {
      cdk_sklist_release (sk_list);
      sk_list = NULL;
    }
  
  *ret_skl = sk_list;
  return rc;
}


/**
 * cdk_sklist_write_onepass:
 * @skl: secret keylist
 * @outp: the stream to write in the data
 * @sigclass: the class of the sig to create
 * @mdalgo: the message digest algorithm
 *
 * Write a one-pass signature for each key in the list into @outp.
 **/
cdk_error_t
cdk_sklist_write_onepass (cdk_keylist_t skl, cdk_stream_t outp,
                          int sigclass, int mdalgo)
{
  cdk_pkt_onepass_sig_t ops;
  cdk_keylist_t r;
  cdk_packet_t pkt;
  size_t skcount;
  int i;
  cdk_error_t rc;
  
  if (!skl || !outp)
    return CDK_Inv_Value;
  
  if (skl->type != CDK_PKT_SECRET_KEY)
    return CDK_Inv_Mode;

  for (skcount = 0, r = skl; r; r = r->next)
    skcount++;
  for (; skcount; skcount--)
    {
      for (i = 0, r = skl; r; r = r->next)
	{
	  if (++i == skcount)
	    break;
	}
      cdk_pkt_alloc (&pkt, CDK_PKT_ONEPASS_SIG);
      ops = pkt->pkt.onepass_sig;
      ops->version = 3;
      cdk_sk_get_keyid (r->key.sk, ops->keyid);
      ops->sig_class = sigclass;
      if (!mdalgo)
	mdalgo = _cdk_sig_hash_for (r->key.sk->pk);
      ops->digest_algo = mdalgo;
      ops->pubkey_algo = r->key.sk->pubkey_algo;
      ops->last = (skcount == 1);
    
      pkt->pkttype = CDK_PKT_ONEPASS_SIG;
      rc = cdk_pkt_write (outp, pkt);
      cdk_pkt_release (pkt);
      if (rc)
	return rc;
    }  
  return 0;
}


/**
 * cdk_sklist_write:
 * @skl: secret keylist
 * @outp: the stream to write in the data
 * @hash: opaque handle for the message digest operations
 * @sigclass: the class of the sig
 * @sigver: version of the sig
 *
 * Complete the sig based on @hash and write all signatures to @outp.
 **/
cdk_error_t
cdk_sklist_write (cdk_keylist_t skl, cdk_stream_t outp, gcry_md_hd_t hash,
		  int sigclass, int sigver)
{
  cdk_keylist_t r;
  cdk_pkt_signature_t sig;
  cdk_packet_t pkt;
  gcry_md_hd_t md;
  const byte *mdbuf;
  int digest_algo;
  cdk_error_t rc;
  
  if (!skl || !outp || !hash)
    return CDK_Inv_Value;
  
  if (skl->type != CDK_PKT_SECRET_KEY)
    return CDK_Inv_Mode;
  
  digest_algo = gcry_md_get_algo (hash);
  for (r = skl; r; r = r->next) 
    {
      cdk_pkt_alloc (&pkt, CDK_PKT_SIGNATURE);
      sig = pkt->pkt.signature;
      sig->version = sigver;
      _cdk_sig_create (r->key.sk->pk, sig);
      if (sig->digest_algo != digest_algo)
	sig->digest_algo = digest_algo;
      sig->sig_class = sigclass;
      gcry_md_copy (&md, hash);
      _cdk_hash_sig_data (sig, md);
      gcry_md_final (md);
      
      mdbuf = gcry_md_read (md, sig->digest_algo);
      rc = cdk_pk_sign (r->key.sk, sig, mdbuf);
      if (!rc)
	{
	  pkt->old_ctb = sig->version == 3? 1 : 0;
	  pkt->pkttype = CDK_PKT_SIGNATURE;
	  rc = cdk_pkt_write (outp, pkt);
	}      
      cdk_pkt_release (pkt);
      gcry_md_close (md);
      if (rc)
	return rc;
    }
  return 0;
}
