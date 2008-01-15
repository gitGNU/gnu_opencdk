/* keygen.c - OpenPGP key generation
 *        Copyright (C) 2002, 2003, 2007 Timo Schulz
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
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "types.h"

/* FIXME: This code probably needs a review but it generates at
         least valid keys (again). */

struct key_ctx_s 
{
  u32 expire_date;
  int algo;
  int len;
  gcry_mpi_t resarr[6];
  size_t n;
  int usage;
  cdk_pubkey_t pk;
  cdk_seckey_t sk;
};


/* Object to hold the key preferences. */
typedef struct 
{
  u16 size;
  byte *d;
} prefstr_t;
    

struct cdk_keygen_ctx_s 
{
  char *user_id;
  cdk_pkt_userid_t id;
  prefstr_t sym;
  prefstr_t hash;
  prefstr_t zip;
  struct 
    {
      unsigned ks_no_modify:1; /* type 23 - keyserver no modify */
      unsigned protect:1;      /* protect all secret keys */
    } flags;
  char *ks_pref_url;
  cdk_pkt_signature_t selfsig;
  cdk_pkt_signature_t bindsig;
  struct key_ctx_s key[2];
  char *pass;
  size_t pass_len;
};


/* Default preferences */
static byte def_sym_prefs[] = {GCRY_CIPHER_AES, GCRY_CIPHER_AES192,
                               GCRY_CIPHER_AES256, GCRY_CIPHER_CAST5,
                               GCRY_CIPHER_3DES};
static byte def_hash_prefs[] = {GCRY_MD_SHA1, GCRY_MD_RMD160, CDK_MD_SHA256};
static byte def_zip_prefs[] = {CDK_COMPRESS_ZIP, CDK_COMPRESS_ZLIB};


static int
check_pref_array (const byte *p, size_t n, enum cdk_pref_type_t type)
{
  size_t i;

  if (!p)
    return 0;
  
  for (i = 0; i < n; i++)
    {
      switch (type)
	{
	case CDK_PREFTYPE_SYM:
	  if (gcry_cipher_test_algo (p[i]))
	    return -1;
	  break;
	case CDK_PREFTYPE_HASH:
	  if (gcry_md_test_algo (p[i]))
	    return -1;
	  break;
	case CDK_PREFTYPE_ZIP:
	  if (p[i] > CDK_COMPRESS_BZIP2)
	    return -1;
	  break;
	default:
	  return -1;
	}
    }
  return 0;
}


int
pk_test_algo (int algo, unsigned int usage_flags)
{
  gcry_error_t err;
  size_t n = usage_flags;  
  
  if (algo < 0 || algo > 110)
    return CDK_Inv_Value;
  err =  gcry_pk_algo_info (algo, GCRYCTL_TEST_ALGO, NULL, &n);
  if (err)
    return map_gcry_error (err);
  return 0;
}



/**
 * cdk_keygen_set_prefs: Set the preferences for the userID
 * @hd: the keygen object
 * @hd: the preference type
 * @array: one-octet array with algorithm numers
 *
 **/
cdk_error_t
cdk_keygen_set_prefs (cdk_keygen_ctx_t hd, enum cdk_pref_type_t type,
                      const byte *array, size_t n)
{
  byte *p;
  
  if (!hd || check_pref_array (array, n, type))
    return CDK_Inv_Value;
  
  switch (type)
    {
    case CDK_PREFTYPE_SYM:
      hd->sym.size = array? n : DIM (def_sym_prefs);
      p = hd->sym.d = cdk_calloc (1, hd->sym.size);
      assert (p);
      memcpy (p, array? array : def_sym_prefs, hd->sym.size);
      break;
      
    case CDK_PREFTYPE_HASH:
      hd->hash.size = array? n : DIM (def_hash_prefs);
      p = hd->hash.d = cdk_calloc (1, hd->hash.size);
      assert (p);
      memcpy (p, array? array : def_hash_prefs, hd->hash.size);
      break;
      
    case CDK_PREFTYPE_ZIP:
      hd->zip.size = array? n : DIM (def_zip_prefs);
      p = hd->zip.d = cdk_calloc (1, hd->zip.size);
      assert (p);
      memcpy (p, array? array : def_zip_prefs, hd->zip.size);
      break;
      
    default:
      return CDK_Inv_Mode;
    }
  
  return 0;
}


/**
 * cdk_keygen_set_name:
 * @hd: the keygen object
 * @name: the name to use
 *
 * It is suggested to use a name in the following format
 * 'First Name' 'Last Name' <email-address.domain>'
 * To avoid charset conflicts, the name will be encoded in utf8.
 **/
void
cdk_keygen_set_name (cdk_keygen_ctx_t hd, const char *name)
{
  if (!hd)
    return;
  
  cdk_free (hd->user_id);
  hd->user_id = NULL;
  if (name)
    hd->user_id = cdk_utf8_encode (name);
}


static int
pk_check_bits (unsigned int bits, int algo)
{
  /* The minimum size of keys is 1024-bits and the maximum size is 4096.
     For DSA, incorrect length value will be corrected. */
  if (bits < 1024)
    return 1024;
  if (algo == GCRY_PK_DSA && bits > 1024)
    return 1024;
  if (bits > 4096)
    return 4096;
  if (bits % 128 != 0)
    bits = bits + (bits % 128);
  return bits;
}


/**
 * cdk_keygen_set_algo_info:
 * @hd: the keygen object.
 * @type: key type (primary=0, subkey=1)
 * @usage: key usage
 * @algo: algorithm compliant with rfc2440
 * @bits: lengt of the key in bits
 *
 * set the length and type of the key
 **/
cdk_error_t
cdk_keygen_set_algo_info (cdk_keygen_ctx_t hd, int type, int usage,
                          enum cdk_pubkey_algo_t algo, unsigned int bits)
{
  cdk_error_t rc;
  
  if (!hd || type < 0 || type > 1)
    return CDK_Inv_Value;
  if (!usage)
    return CDK_Inv_Mode;
  
  rc = pk_test_algo (algo, usage);
  if (rc)
    return rc;
  if (usage & CDK_KEY_USG_AUTH)
    hd->key[type].usage |= 0x20;
  if (usage & CDK_KEY_USG_SIGN)
    hd->key[type].usage |= (0x01 | 0x02);
  if (usage & CDK_KEY_USG_ENCR)
    hd->key[type].usage |= (0x04 | 0x08);
  rc = pk_test_algo (algo, usage);
  
  hd->key[type].algo = algo;
  hd->key[type].len = pk_check_bits (bits, algo);
  return 0;
}


/**
 * cdk_keygen_set_keyserver_flags:
 * @hd: the handle
 * @no_modify: set the keyserver no modify flag for the key
 * @pref_url: set the preferred keyser URL.
 *
 * Set some keyserver specific options for the new key.
 **/
int
cdk_keygen_set_keyserver_flags (cdk_keygen_ctx_t hd, int no_modify,
                                const char *pref_url)
{
  if (!hd)
    return CDK_Inv_Value;
  if (no_modify)
    hd->flags.ks_no_modify = 1;
  if (pref_url) 
    {
      hd->ks_pref_url = cdk_strdup (pref_url);
      if (!hd->ks_pref_url)
	return CDK_Out_Of_Core;
    }
  return 0;
}

    
/**
 * cdk_keygen_set_expire_date:
 * @hd: keygen object
 * @type: key type( 0=primary, 1=seconardy)
 * @timestamp: the date the key should expire
 *
 * set the expire date of the requested key
 **/
int
cdk_keygen_set_expire_date (cdk_keygen_ctx_t hd, int type, long timestamp)
{
  if (!hd || type < 0 || type > 1)
    return CDK_Inv_Value;
  if (timestamp < 0 || timestamp < (u32)time (NULL))
    timestamp = 0;
  hd->key[type].expire_date = timestamp;
  return 0;
}


void
cdk_keygen_set_passphrase (cdk_keygen_ctx_t hd, const char *pass)
{
  size_t n;
  
  if (!hd || !pass)
    return;
  
  n = strlen (pass);  
  wipemem (hd->pass, hd->pass_len);
  cdk_free (hd->pass);
  hd->pass = cdk_salloc (n + 1, 1);
  if (hd->pass) 
    {
      memcpy (hd->pass, pass, n);
      hd->pass[n] = '\0';
      hd->pass_len = n;
      hd->flags.protect = 1;
    }
}


static int
read_mpibuf_from_sexp (gcry_sexp_t sk, int pk_algo, 
		       gcry_mpi_t *resarr, size_t *r_nresout)
{
  gcry_sexp_t list;
  const char *n;
  char buf[2];
  size_t i;
  
  if (is_DSA (pk_algo))
    n = "pqgyx";
  else if (is_ELG (pk_algo))
    n = "pgyx";
  else if (is_RSA (pk_algo)) 
    n = "nedpqu";
  else 
    return CDK_Inv_Algo;
  
  for (i = 0; n && *n; n++) 
    {
      buf[0] = *n; buf[1] = '\0';
      list = gcry_sexp_find_token (sk, buf, 0);
      if (!list)
	continue;
      resarr[i++] = gcry_sexp_nth_mpi (list, 1, 0);
      gcry_sexp_release (list);
    }
  
  *r_nresout = i;
  return 0;
}


static int
pk_genkey (gcry_sexp_t *r_s_key, int pk_algo, int is_subkey, int n)
{
  gcry_sexp_t s_key = NULL, s_params = NULL;
  gcry_error_t err;
    
  if (is_DSA (pk_algo))
    err = gcry_sexp_build (&s_params, NULL, "(genkey(dsa(nbits %d)))", n);
  else if (is_subkey && is_ELG (pk_algo))
    err = gcry_sexp_build (&s_params, NULL, "(genkey(elg(nbits %d)))", n);
  else if (is_RSA( pk_algo))
    err = gcry_sexp_build (&s_params, NULL, "(genkey(rsa(nbits %d)))", n);
  else
    return CDK_Inv_Algo;
  if (err)
    return map_gcry_error (err);
  
  err = gcry_pk_genkey (&s_key, s_params);
  gcry_sexp_release (s_params);
  if (!err)
    *r_s_key = s_key;
  else 
    {
      gcry_sexp_release (s_key);
      *r_s_key = NULL;
      return map_gcry_error (err);
    }
  
  return 0;
}

/**
 * cdk_keygen_start: kick off the key generation
 * @hd: the keygen object
 *
 **/
cdk_error_t
cdk_keygen_start (cdk_keygen_ctx_t hd)
{
  gcry_sexp_t s_key = NULL;
  cdk_error_t rc = 0;
  
  if (!hd || !hd->user_id)
    return CDK_Inv_Value;
  if (is_ELG( hd->key[0].algo))
    return CDK_Inv_Mode;
  if (!hd->key[0].len)
    hd->key[0].len = 1024;
  
  /* use the user did not set any preferences, use the default values */
  if (!hd->sym.d)
    cdk_keygen_set_prefs (hd, CDK_PREFTYPE_SYM, NULL, 0);
  if (!hd->hash.d)
    cdk_keygen_set_prefs (hd, CDK_PREFTYPE_HASH, NULL, 0);
  if (!hd->zip.d)
    cdk_keygen_set_prefs (hd, CDK_PREFTYPE_ZIP, NULL, 0);

  rc = pk_genkey (&s_key, hd->key[0].algo, 0, hd->key[0].len);
  if (!rc)
    rc = read_mpibuf_from_sexp (s_key, hd->key[0].algo, 
				hd->key[0].resarr, &hd->key[0].n);
  gcry_sexp_release (s_key);
  if (!rc && hd->key[1].algo && hd->key[1].len)
    {
      rc = pk_genkey (&s_key, hd->key[1].algo, 1, hd->key[1].len);
      if (!rc) 
	rc = read_mpibuf_from_sexp (s_key, hd->key[1].algo,
				    hd->key[1].resarr, &hd->key[1].n);
      gcry_sexp_release (s_key);
    }
  return rc;
}


static int
gcry_mpi_to_native (cdk_keygen_ctx_t hd, size_t nkey, int type,
                    cdk_pubkey_t pk, cdk_seckey_t sk)
{
  gcry_mpi_t *resarr;
  size_t i, j;
  
  if (!hd || (!pk && !sk) || (sk && pk))
    return CDK_Inv_Value;
  if (type < 0 || type > 1)
    return CDK_Inv_Value;
  
  resarr = hd->key[type].resarr;
  if (pk)
    {
      nkey = cdk_pk_get_npkey (pk->pubkey_algo);
      for (j=0; j < nkey; j++)
	pk->mpi[j] = gcry_mpi_copy (resarr[j]);
    }
  if (sk)
    {
      i = cdk_pk_get_npkey (sk->pubkey_algo);
      nkey = cdk_pk_get_nskey (sk->pubkey_algo);
      for (j=0; j < nkey; j++)
	sk->mpi[j] = gcry_mpi_copy (resarr[j+i]);
    }
  
  return 0;
}

  
static cdk_pubkey_t
pk_create (cdk_keygen_ctx_t hd, int type)
{
  cdk_pubkey_t pk;
  size_t npkey = 0;
  cdk_error_t rc;
  
  if (type < 0 || type > 1)
    return NULL;
  pk = cdk_calloc (1, sizeof *pk);
  if (!pk)
    return NULL;
  pk->version = 4;
  pk->pubkey_algo = hd->key[type].algo;
  pk->timestamp = (u32)time (NULL);
  if (hd->key[type].expire_date)
    pk->expiredate = pk->timestamp + hd->key[type].expire_date;
  npkey = cdk_pk_get_npkey (pk->pubkey_algo);
  rc = gcry_mpi_to_native (hd, npkey, type, pk, NULL);
  if (rc) 
    {
      cdk_free (pk);
      pk = NULL;
    }
  return pk;
}


static cdk_seckey_t
sk_create (cdk_keygen_ctx_t hd, int type)
{
  cdk_seckey_t sk;
  int nskey, rc = 0;
  
  if (type < 0 || type > 1)
    return NULL;
  sk = cdk_calloc (1, sizeof *sk);
  if (!sk)
    return NULL;
  _cdk_copy_pubkey (&sk->pk, hd->key[type].pk);
  sk->version = 4;
  sk->pubkey_algo = hd->key[type].algo;
  sk->csum = 0;
  sk->is_protected = 0;
  nskey = cdk_pk_get_nskey (sk->pubkey_algo);
  rc = gcry_mpi_to_native (hd, nskey, type, NULL, sk);
  if (rc) 
    {    
      cdk_free (sk);
      sk = NULL;
    }
  return sk;
}


static cdk_pkt_userid_t
uid_create (cdk_keygen_ctx_t hd)
{
  cdk_pkt_userid_t id;
  
  if (!hd->user_id)
    return NULL;
  id = cdk_calloc (1, sizeof * id + strlen (hd->user_id) + 1);
  if (!id)
    return NULL;
  strcpy (id->name, hd->user_id);
  id->len = strlen (hd->user_id);
  return id;
}


static cdk_pkt_signature_t
sig_subkey_create (cdk_keygen_ctx_t hd)
{
  gcry_md_hd_t md;
  cdk_subpkt_t node;
  cdk_pkt_signature_t sig;
  cdk_pubkey_t pk = hd->key[0].pk;
  cdk_pubkey_t sub_pk = hd->key[1].pk;
  cdk_seckey_t sk = hd->key[0].sk;
  byte buf[4];
  cdk_error_t rc;
  
  sig = cdk_calloc( 1, sizeof * sig );
  if( !sig )
    return NULL;
  _cdk_sig_create (pk, sig);
  sig->sig_class = 0x18;
  sig->digest_algo = GCRY_MD_SHA1;
  
  if( sub_pk->expiredate ) {
    _cdk_u32tobuf( sub_pk->expiredate - sub_pk->timestamp, buf );
    node = cdk_subpkt_new( 4 );
    if (node)
      {
	cdk_subpkt_init (node, CDK_SIGSUBPKT_KEY_EXPIRE, buf, 4);
	cdk_subpkt_add (sig->hashed, node);
      }
  }
  
  buf[0] = hd->key[1].usage;;
  node = cdk_subpkt_new (1);
  if (node) 
    {
      cdk_subpkt_init (node, CDK_SIGSUBPKT_KEY_FLAGS, buf, 1);
      cdk_subpkt_add (sig->hashed, node);
    }
  
  if (gcry_md_open (&md, sig->digest_algo, 0))
    {
      _cdk_free_signature (sig);
      return NULL;
    }
  
  _cdk_hash_pubkey (pk, md, 0);
  _cdk_hash_pubkey( sub_pk, md, 0 );
  rc = _cdk_sig_complete( sig, sk, md );
  gcry_md_close (md);
  if (rc) 
    {
      _cdk_free_signature (sig);
      return NULL;
    }
  return sig;
}


static cdk_pkt_signature_t
sig_self_create( cdk_keygen_ctx_t hd )
{
  gcry_md_hd_t md;
  cdk_subpkt_t node;
  cdk_pkt_signature_t sig;
  cdk_pubkey_t pk = hd->key[0].pk;
  cdk_pkt_userid_t id = hd->id;
  cdk_seckey_t sk = hd->key[0].sk;
  u32 keyid[2];
  byte buf[8], * p;
  cdk_error_t rc;
  
  sig = cdk_calloc (1, sizeof *sig);
  if (!sig)
        return NULL;
  sig->version = 4;
  sig->timestamp = (u32)time (NULL);
  sig->sig_class = 0x13;
  sig->pubkey_algo = hd->key[0].algo;
  sig->digest_algo = GCRY_MD_SHA1;

  _cdk_u32tobuf (sig->timestamp, buf);
  sig->hashed = node = cdk_subpkt_new (4);
  if (node)
    cdk_subpkt_init( node, CDK_SIGSUBPKT_SIG_CREATED, buf, 4 );
  
  p = hd->sym.d;
  node = cdk_subpkt_new( hd->sym.size + 1 );
  if( node ) {
    cdk_subpkt_init( node, CDK_SIGSUBPKT_PREFS_SYM, p, hd->sym.size );
    cdk_subpkt_add( sig->hashed, node );
  }
  
  p = hd->hash.d;
  node = cdk_subpkt_new( hd->hash.size + 1 );
  if( node ) {
    cdk_subpkt_init( node, CDK_SIGSUBPKT_PREFS_HASH, p, hd->hash.size );
    cdk_subpkt_add( sig->hashed, node );
  }
  
  p = hd->zip.d;
  node = cdk_subpkt_new( hd->zip.size + 1 );
  if( node ) {
    cdk_subpkt_init( node, CDK_SIGSUBPKT_PREFS_ZIP, p, hd->zip.size );
    cdk_subpkt_add( sig->hashed, node );
  }
  
  /* By default set the MDC feature. */
  buf[0] = 0x01;
  node = cdk_subpkt_new( 1 );
  if( node ) {
    cdk_subpkt_init( node, CDK_SIGSUBPKT_FEATURES, buf, 1 );
    cdk_subpkt_add( sig->hashed, node );
  }

  node = cdk_subpkt_new (1);
  if (node)
    {
      buf[0] = hd->key[0].usage;
      cdk_subpkt_init (node, CDK_SIGSUBPKT_KEY_FLAGS, buf, 1);
      cdk_subpkt_add (sig->hashed, node);
    }
  
  if( hd->flags.ks_no_modify ) {
    buf[0] = 0x80;
    node = cdk_subpkt_new( 1 );
    if( node ) {
      cdk_subpkt_init( node, CDK_SIGSUBPKT_KS_FLAGS, buf, 1 );
      cdk_subpkt_add( sig->hashed, node );
    }
  }
  
  if( hd->ks_pref_url ) {
    node = cdk_subpkt_new( strlen( hd->ks_pref_url ) + 1 );
    if( node ) {
      cdk_subpkt_init( node, CDK_SIGSUBPKT_PREF_KS,
		       hd->ks_pref_url, strlen( hd->ks_pref_url ) );
      cdk_subpkt_add( sig->hashed, node );
    }
  }
  
  if( pk->expiredate ) {
    node = cdk_subpkt_new( 4 );
    if( node ) {
      _cdk_u32tobuf( pk->expiredate - pk->timestamp, buf );
      cdk_subpkt_init( node, CDK_SIGSUBPKT_KEY_EXPIRE, buf, 4 );
      cdk_subpkt_add( sig->hashed, node );
    }
  }
  
  sig->unhashed = node = cdk_subpkt_new( 8 );
  if( node ) {
    cdk_pk_get_keyid( pk, keyid );
    _cdk_u32tobuf( keyid[0], buf );
    _cdk_u32tobuf( keyid[1], buf + 4 );
    cdk_subpkt_init( node, CDK_SIGSUBPKT_ISSUER,  buf, 8 );
  }
  
  if (gcry_md_open( &md, sig->digest_algo, 0 ))
    {
      _cdk_free_signature (sig);
      return NULL;
    }
  
  _cdk_hash_pubkey( pk, md, 0 );
  _cdk_hash_userid( id, sig->version == 4, md );
  rc = _cdk_sig_complete( sig, sk, md );
  gcry_md_close( md );
  if( rc ) {
    _cdk_free_signature( sig );
    return NULL;
  }  
  return sig;
}


static void
correct_subkey_algo (cdk_pubkey_t pk, int *r_can_encr, int *r_can_sign)
{
  /* RSA_E and RSA_S are obsolete so we set the algo to RSA and return
     the key usage instead. */
  if (pk->pubkey_algo == CDK_PK_RSA_E)
    {
      *r_can_sign = 0;
      *r_can_encr = 1;
    }
  else if (pk->pubkey_algo == CDK_PK_RSA_S)
    {
      *r_can_encr = 0;
      *r_can_sign = 1;
    } 
  else if (pk->pubkey_algo == CDK_PK_RSA)
    {
      *r_can_sign = 1;
      *r_can_encr = 1;
    }
  else if (pk->pubkey_algo == CDK_PK_ELG_E)
    {
      *r_can_encr = 1;
      *r_can_sign = 0;
    }
  if (is_RSA (pk->pubkey_algo))
    pk->pubkey_algo = CDK_PK_RSA;
}
        

/**
 * cdk_keygen_save: save the generated keys to disk
 * @hd: the keygen object
 * @pub: name of the file to store the public key
 * @sec: name of the file to store the secret key
 *
 **/
cdk_error_t
cdk_keygen_save (cdk_keygen_ctx_t hd, const char *pubf, const char *secf)
{
  cdk_stream_t out = NULL;
  cdk_error_t rc;

  hd->key[0].pk = pk_create (hd, 0);
  if (!hd->key[0].pk)
    return CDK_Inv_Packet;
  hd->key[0].sk = sk_create (hd, 0);
  if (!hd->key[0].sk)
    return CDK_Inv_Packet;
  hd->id = uid_create (hd);
  if (!hd->id)
    return CDK_Inv_Packet;
  hd->selfsig = sig_self_create (hd);
  if (!hd->selfsig)
    return CDK_Inv_Packet;
  
  rc = cdk_stream_create (pubf, &out);
  if (rc)
    return rc;
  
  rc = _cdk_pkt_write2 (out, CDK_PKT_PUBLIC_KEY, hd->key[0].pk);
  if (!rc)
    rc = _cdk_pkt_write2 (out, CDK_PKT_USER_ID, hd->id);
  if (!rc)
    rc = _cdk_pkt_write2 (out, CDK_PKT_SIGNATURE, hd->selfsig);
  if (rc)
    goto fail;
  
  if (hd->key[1].algo) 
    {
      hd->key[1].pk = pk_create (hd, 1);
      /*correct_subkey_algo (hd->key[1].pk, &can_encr, &can_sign);*/
      hd->bindsig = sig_subkey_create (hd);
      rc = _cdk_pkt_write2 (out, CDK_PKT_PUBLIC_SUBKEY, hd->key[1].pk);
      if (!rc)
	rc = _cdk_pkt_write2 (out, CDK_PKT_SIGNATURE, hd->bindsig);
      if (rc)
	goto fail;
    }
  
  cdk_stream_close (out);
  out = NULL;
  
  rc = cdk_stream_create (secf, &out);
  if (rc)
    goto fail;
  
  if (hd->flags.protect) 
    {
      rc = cdk_sk_protect (hd->key[0].sk, hd->pass);
      if (rc)
	goto fail;
    }
  
  rc = _cdk_pkt_write2 (out, CDK_PKT_SECRET_KEY, hd->key[0].sk);
  if (!rc)
    rc = _cdk_pkt_write2 (out, CDK_PKT_USER_ID, hd->id);
  if (!rc)
    rc = _cdk_pkt_write2 (out, CDK_PKT_SIGNATURE, hd->selfsig);
  if (rc)
    goto fail;

  if (hd->key[1].algo)
    {
      hd->key[1].sk = sk_create (hd, 1);
      if (hd->flags.protect)
	rc = cdk_sk_protect (hd->key[1].sk, hd->pass);
      if (!rc)
	rc = _cdk_pkt_write2 (out, CDK_PKT_SECRET_SUBKEY, hd->key[1].sk);
    }
  
  fail:
  cdk_stream_close (out);
  return rc;
}


/**
 * cdk_keygen_free: free the keygen object
 * @hd: the keygen object
 *
 **/
void
cdk_keygen_free (cdk_keygen_ctx_t hd)
{
  if (!hd)
    return;
  cdk_pk_release (hd->key[0].pk);
  cdk_pk_release (hd->key[1].pk);
  cdk_sk_release (hd->key[0].sk);
  cdk_sk_release (hd->key[1].sk);
  _cdk_free_userid( hd->id );
  _cdk_free_signature (hd->selfsig);
  _cdk_free_signature (hd->bindsig);
  cdk_free (hd->sym.d);
  cdk_free (hd->hash.d);
  cdk_free (hd->zip.d);
  wipemem (hd->pass, hd->pass_len);
  cdk_free (hd->pass);
  _cdk_free_mpibuf (hd->key[0].n, hd->key[0].resarr);
  _cdk_free_mpibuf (hd->key[1].n, hd->key[1].resarr);
  cdk_free (hd->user_id);
  cdk_free (hd);
}


/**
 * cdk_keygen_new:
 * @r_hd: the new object
 *
 * allocate a new key generation context.
 **/
cdk_error_t
cdk_keygen_new (cdk_keygen_ctx_t *r_hd)
{
  cdk_keygen_ctx_t hd;
  
  if (!r_hd)
    return CDK_Inv_Value;
  hd = cdk_calloc (1, sizeof *hd);
  if (!hd)
    return CDK_Out_Of_Core;
  *r_hd = hd;
  return 0;
}
