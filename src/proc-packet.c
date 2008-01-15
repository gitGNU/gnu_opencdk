/* proc-packet.c
 *        Copyright (C) 2001, 2002, 2003, 2007 Timo Schulz
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
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "types.h"
#include "filters.h"
#include "stream.h"
#include "packet.h"

struct mainproc_ctx_s {
  cdk_dek_t dek;
  cdk_stream_t s;
  cdk_kbnode_t node;
  cdk_stream_t tmpfp;
  cdk_stream_t datafp; /* For detached signatures, this is the data stream. */
  cdk_seckey_t last_sk;
  unsigned int datafp_close:1;
  struct {
    unsigned present:1;
    unsigned one_pass:1;
    gcry_md_hd_t md;
    unsigned int md_close:1;
    int digest_algo;
    int is_expired;
    cdk_pkt_pubkey_t pk;
    unsigned pt_offset;
  } sig;
  unsigned eof_seen:1;
  unsigned key_seen:1;
  char *file;
  const char *output;
};
typedef struct mainproc_ctx_s *mainproc_ctx_t;


/* Return 1 if @file has an openpgp extension. */
static int
is_openpgp_ext (const char *file)
{
  return (stristr (file, ".asc") || stristr (file, ".sig") ||
	  stristr (file, ".gpg") || stristr (file, ".pgp")) ? 1 : 0;
}


/* Hash the data file for the given detached signature and return
   the digest context in @r_md. */
static cdk_error_t
hash_data_file (mainproc_ctx_t c, int digest_algo, gcry_md_hd_t *r_md)
{
  md_filter_t *mfx;
  char *dat_file;
  cdk_error_t rc;

  if (!c->datafp && (!c->file || !is_openpgp_ext (c->file)))
    return CDK_General_Error;
  
  /* If we have no data stream, the data file must be in the same
     directory as the sig file and must be derrived like this
     test-data.sig -> test.data (data file) */
  if (!c->datafp)
    {
      dat_file = cdk_strdup (c->file);
      if (!dat_file)
	return CDK_Out_Of_Core;
      dat_file[strlen (dat_file) - 4] = '\0';
  
      _cdk_log_debug ("detached sig: hash data file '%s'\n", dat_file);
      rc = cdk_stream_open (dat_file, &c->datafp);
      if (rc)
	{
	  /* It is not very useful to issue a 'no such file or dir' error
	     because a lot of files are involved. Thus we indicate the no
	     data error, to give a hint that some data is missing. */
	  if (rc == CDK_File_Error)
	    rc = CDK_No_Data;
	  return rc;
	}     
      c->datafp_close = 1;
      cdk_free (dat_file);
    }  
  
  cdk_stream_set_hash_flag (c->datafp, digest_algo);
  cdk_stream_read (c->datafp, NULL, 0);
  mfx = _cdk_stream_get_opaque (c->datafp, fHASH);
  if (mfx && mfx->md)
    gcry_md_copy (r_md, mfx->md);
  return 0;
}


static cdk_error_t
handle_symkey_enc (mainproc_ctx_t c, cdk_ctx_t hd, cdk_packet_t pkt)
{
  cdk_pkt_symkey_enc_t key;
  cdk_error_t rc;
  char *pw;
  
  assert (pkt->pkttype == CDK_PKT_SYMKEY_ENC);
  
  c->key_seen = 1;
  if (c->dek)
    return 0; /* we already decrypted the session key */
  
  pw = _cdk_passphrase_get (hd, "Enter passphrase for symmetric decryption: ");
  if (!pw)
    return CDK_No_Passphrase;
  
  key = pkt->pkt.symkey_enc;
  rc = cdk_dek_from_passphrase (&c->dek, key->cipher_algo, key->s2k, 0, pw);

  wipemem (pw, strlen (pw));
  cdk_free (pw);
  return rc;
}


static cdk_error_t
handle_pubkey_enc (mainproc_ctx_t c, cdk_ctx_t hd, cdk_packet_t pkt)
{
  cdk_pkt_pubkey_enc_t enc;
  cdk_pkt_seckey_t sk = NULL;
  u32 sk_keyid[2];
  cdk_error_t rc;
  
  assert (pkt->pkttype == CDK_PKT_PUBKEY_ENC);

  /* Set a marker to allow further packets to know whether s
     DEK has been already seen. */
  c->key_seen = 1;
  enc = pkt->pkt.pubkey_enc;  
  if (c->dek)
    return 0; /* We already decrypted the session key. */
  
  /* We checked before that there is at least one secret key so we
     skip this packet and continue without errors. */
  if (cdk_keydb_check_sk (hd->db.sec, enc->keyid))
    return 0;
  
  if (c->last_sk != NULL)
    {
      cdk_sk_get_keyid (c->last_sk, sk_keyid);
      if (sk_keyid[0] == enc->keyid[0] &&
	  sk_keyid[1] == enc->keyid[1])
	sk = c->last_sk;
      else
	{
	  /* key ID does not match, release key. */
	  cdk_sk_release (c->last_sk);
	  c->last_sk = NULL;
	  sk = NULL;
	}
    }
   
  /* The last secret key did not match and needs to be replaced. */
  if (sk == NULL)
    {      
      rc = cdk_keydb_get_sk (hd->db.sec, enc->keyid, &sk);
      if (rc)
	return rc;
      cdk_sk_release (c->last_sk);
      c->last_sk = sk;
    }  

  rc = cdk_dek_extract (&c->dek, hd, enc, sk);
  return rc;
}


static cdk_error_t
rfc1991_get_sesskey (cdk_dek_t *r_dek, cdk_ctx_t hd)
{
  cdk_s2k_t s2k;
  char *pw;
  cdk_error_t rc;

  if (!r_dek)
    return CDK_Inv_Value;
  
  /* The RFC1991 mode implies to use MD5 and the simple S2K method
     to convert the passphrase to the DEK. */
  rc = cdk_s2k_new (&s2k, 0, GCRY_MD_MD5, NULL);
  if (rc) 
    return rc;
  
  pw = _cdk_passphrase_get (hd, "Enter Passphrase: ");
  if (!pw)
    return CDK_No_Passphrase;
  
  /* Because IDEA is not available, the code is useless for now. */
  rc = cdk_dek_from_passphrase (r_dek, CDK_CIPHER_IDEA, s2k, 0, pw);

  wipemem (pw, strlen (pw));
  cdk_free (pw);
  cdk_s2k_free (s2k);
  return rc;
}

  
static cdk_error_t
handle_encrypted (mainproc_ctx_t c, cdk_ctx_t hd, cdk_packet_t pkt)
{
  cdk_pkt_encrypted_t enc;
  int pgp2_compat = 0;
  int use_mdc = pkt->pkttype == CDK_PKT_ENCRYPTED_MDC;
  int pkttype = pkt->pkttype;
  cdk_error_t rc;
  
  assert (CDK_PKT_IS_ENCRYPTED (pkttype));
  
  if (!c->dek) 
    {
      if (!pgp2_compat)
	return CDK_Error_No_Key;
      else if (!c->key_seen) 
	{	
	  _cdk_log_debug ("RFC1991 message was detected.\n");
	  rc = rfc1991_get_sesskey (&c->dek, hd);
	  if (rc)
	    return rc;
	}
      else
	return CDK_Error_No_Key;
    }
  
  enc = pkt->pkt.encrypted;
  cdk_stream_set_cipher_flag (enc->buf, c->dek, use_mdc);
  rc = cdk_stream_read (enc->buf, NULL, 0);
  if (!rc)
    c->s = enc->buf;
  else
    rc = _cdk_stream_get_errno (enc->buf);
  return rc;
}


static cdk_error_t
handle_compressed (mainproc_ctx_t c, cdk_packet_t pkt)
{
  cdk_pkt_compressed_t zip;
  cdk_error_t rc;
  
  assert (pkt->pkttype == CDK_PKT_COMPRESSED);
  
  zip = pkt->pkt.compressed;
  cdk_stream_set_compress_flag (c->s, zip->algorithm, 0);
  rc = cdk_stream_read (c->s, NULL, 0);
  if (rc)
    rc = _cdk_stream_get_errno (c->s);
  return rc;
}


static cdk_error_t
handle_onepass_sig (mainproc_ctx_t c, cdk_packet_t pkt)
{
  gcry_error_t err;
    
  assert (pkt->pkttype == CDK_PKT_ONEPASS_SIG);
  
  if (c->sig.md)
    return 0; /* already open */
  
  c->sig.digest_algo = pkt->pkt.onepass_sig->digest_algo;
  if (gcry_md_test_algo (c->sig.digest_algo))
    return CDK_Inv_Algo;
  err  = gcry_md_open (&c->sig.md, c->sig.digest_algo, 0);
  if (err)
    return map_gcry_error (err);
  c->sig.md_close = 1;
  return 0;
}


static cdk_error_t
handle_literal (mainproc_ctx_t c, cdk_packet_t pkt, cdk_stream_t *ret_out)
{
  literal_filter_t *pfx;
  cdk_pkt_literal_t pt;
  cdk_stream_t out;
  const char *s;
  cdk_error_t rc;
  
  assert (pkt->pkttype == CDK_PKT_LITERAL);
  
  if (!ret_out)
    return CDK_Inv_Value;

  pt = pkt->pkt.literal;
  cdk_stream_seek (c->s, c->sig.present? c->sig.pt_offset : 0);
  cdk_stream_set_literal_flag (c->s, 0, NULL);
  pfx = _cdk_stream_get_opaque (c->s, fLITERAL);
  if (c->sig.present)
    {
      _cdk_log_debug ("handle_literal: enable hash algo %d\n", 
		      c->sig.digest_algo);
      if (pfx)
	pfx->md = c->sig.md;
    }

  /* Start the filter chain because we need the name from the literal
     packet now, if it exists. */
  cdk_stream_read (c->s, NULL, 0);
  
  if (!c->tmpfp)
    {
      /* FIXME: We need to handle the _CONSOLE name and make sure
         that the name in the literal packet is stripped to avoid
         to overwrite data. Stripped in this context means, we only
         will use the name, not a path that might be stored along with
         the name. */
      
      /* If the user gave an output file, we need to use it because
         other functions might expect the plain text in this file. */
      if (c->output)
	s = c->output;
      else if (pfx && pfx->filename)
	{
	  /* If no output were given, we use the name derrived from
	     the literal packet. */
	  s = pfx->filename;
	  _cdk_log_debug ("handle_literal: file name '%s'\n", s);
	}      
      else
	{
	  _cdk_log_debug ("handle_literal: no file name and no output\n");
	  return CDK_Inv_Mode;
	}
      rc = cdk_stream_create (s, ret_out);
      if (rc)
	return rc;
    }
  else
    *ret_out = c->tmpfp;
  out = *ret_out;  
  return cdk_stream_kick_off (c->s, out);
}


static byte*
mpi_encode (cdk_pkt_signature_t sig)
{
  byte *p, buf[MAX_MPI_BYTES];
  size_t len, i, nsig, pos;
  size_t bits, nbytes;
  
  nsig = cdk_pk_get_nsig (sig->pubkey_algo);
  for (i = 0, len = 0; i < nsig; i++) 
    {
      bits = gcry_mpi_get_nbits (sig->mpi[i]);
      len += (bits+7)/8 + 2;
    }
  p = cdk_calloc (1, len + 1);
  if (!p)
    return NULL;
  for (i = 0, pos = 0; i < nsig; i++) 
    {
      if (gcry_mpi_print (GCRYMPI_FMT_PGP, buf, MAX_MPI_BYTES,
			  &nbytes, sig->mpi[i]))
	{
	  cdk_free (p);
	  return NULL;
	}     
      memcpy (p + pos, buf, nbytes);
      pos += nbytes;
    }
  return p;
}


static void
store_verify_result (cdk_ctx_t hd, cdk_pkt_signature_t sig,
                     cdk_verify_result_t res)
{
  cdk_subpkt_t node;
  const byte *d;
  size_t n;
  
  res->sig_len = gcry_mpi_get_nbits (sig->mpi[0]);
  res->sig_ver = sig->version;
  res->keyid[0] = sig->keyid[0];
  res->keyid[1] = sig->keyid[1];
  res->created = sig->timestamp;
  res->pubkey_algo = sig->pubkey_algo;
  res->digest_algo = sig->digest_algo;
  if (sig->flags.expired)
    res->sig_flags |= CDK_FLAG_SIG_EXPIRED;
  res->sig_data = mpi_encode (sig);
  node = cdk_subpkt_find (sig->hashed, CDK_SIGSUBPKT_SIGNERS_UID);
  if (!node)
    node = cdk_subpkt_find (sig->unhashed, CDK_SIGSUBPKT_SIGNERS_UID);
  if (node)
    {
      d = cdk_subpkt_get_data (node, NULL, &n);
      if (!d)
	return;
      if (_cdk_keydb_check_userid (hd->db.pub, sig->keyid, (const char*)d))
	{
	  /* Check if the signer's user-id is really part of the
	   key which was used for signing. this basic check avoid
	   forged signatures by mallory. */
	  _cdk_log_debug ("user-id could not found on the issuser key.");
	  return;
        }
      res->user_id = cdk_calloc (1, n+1);
      assert (res->user_id);
      memcpy (res->user_id, d, n);
    }
  node = cdk_subpkt_find (sig->hashed, CDK_SIGSUBPKT_POLICY);
  if (node) 
    {
      d = cdk_subpkt_get_data (node, NULL, &n);
      if (!d)
	return;
      res->policy_url = cdk_calloc (1, n+1);
      assert (res->policy_url);
      memcpy (res->policy_url, d, n);
  }
}

    
static cdk_error_t
handle_signature (cdk_ctx_t hd, mainproc_ctx_t c, cdk_packet_t pkt)
{
  cdk_verify_result_t res;
  cdk_pkt_signature_t sig;
  u32 keyid[2];
  cdk_error_t rc;

  assert (pkt->pkttype == CDK_PKT_SIGNATURE);
  
  if (!c->sig.present)
    return CDK_Inv_Packet;
  
  _cdk_result_verify_free (hd->result.verify);
  res = hd->result.verify = _cdk_result_verify_new ();
  if (!hd->result.verify)
    return CDK_Out_Of_Core;
  
  sig = pkt->pkt.signature;
  if (!c->sig.one_pass && !c->sig.md)
    {
      if (gcry_md_test_algo (sig->digest_algo))
	return CDK_Inv_Algo;
      rc = hash_data_file (c, sig->digest_algo, &c->sig.md);
      c->sig.md_close = 1;
      if (rc)
	return rc;
    }
  
  cdk_sig_get_keyid (sig, keyid);
  store_verify_result (hd, sig, res);
  
  /* It might be possible this function is entered twice. */
  cdk_pk_release (c->sig.pk);
  rc = cdk_keydb_get_pk (hd->db.pub, keyid, &c->sig.pk);
  if (rc) 
    {
      res->sig_status = CDK_SIGSTAT_NOKEY;
      return rc;
    }
  
  if (c->sig.pk->is_revoked)
    res->sig_flags |= CDK_FLAG_KEY_REVOKED;
  if (c->sig.pk->has_expired)
    res->sig_flags |= CDK_FLAG_KEY_EXPIRED;

  rc = _cdk_sig_check (c->sig.pk, sig, c->sig.md, &c->sig.is_expired);
  res->sig_status = !rc? CDK_SIGSTAT_GOOD : CDK_SIGSTAT_BAD;
  _cdk_log_debug ("handle_signature: %s sig from %08lX%08lX (exp %d)\n",
		  !rc? "good" : "bad/invalid",
		  keyid[0], keyid[1], c->sig.is_expired);
  return rc;
}


/* Release the mainproc context handle. */
static void
free_mainproc (mainproc_ctx_t c)
{
  if (!c)
    return;
  cdk_sk_release (c->last_sk);
  cdk_kbnode_release (c->node);
  c->node = NULL;
  if (c->datafp && c->datafp_close)
    cdk_stream_close (c->datafp);
  c->datafp = NULL;
  /* It is possible that the MD was only a reference and we
     do not close such handles. */
  if (c->sig.md != NULL && c->sig.md_close)
    {      
      gcry_md_close (c->sig.md);
      c->sig.md = NULL;
    }
  if (c->sig.pk != NULL)
    {
      cdk_pk_release (c->sig.pk);
      c->sig.pk = NULL;
    }
  cdk_free (c->file);
  c->file = NULL;
  cdk_free (c->dek);
  c->dek = NULL;
  cdk_free (c);
}


static cdk_error_t
do_proc_packets (cdk_ctx_t hd, mainproc_ctx_t c, cdk_stream_t inp,
                 cdk_stream_t *ret_out)
{
  cdk_packet_t pkt = NULL;
  cdk_kbnode_t n = NULL, node;
  const char *s;
  off_t npos;
  int lit_seen;
  cdk_error_t rc;
  
  if (!hd || !c)
    return CDK_Inv_Value;
  
  *ret_out = NULL;
  s = _cdk_stream_get_fname (inp);
  c->file = cdk_strdup (s? s : " ");
  if (!c->file) 
    return CDK_Out_Of_Core;
  
  lit_seen = 0; /* We have not seen any literal packets, yet. */
  rc = 0;
  while (!cdk_stream_eof (inp)) 
    {
      cdk_pkt_new (&pkt);
      rc = cdk_pkt_read (inp, pkt);
      _cdk_log_debug ("proc_packets: type=%d old_ctb=%d len=%d (%d)\n",
		      pkt->pkttype, pkt->old_ctb, pkt->pktlen, rc);
      if (rc == CDK_EOF)
	c->eof_seen = 1;
      if (rc)
	{
	  cdk_pkt_release (pkt);
	  break;
	}     
 
      n = cdk_kbnode_new (pkt);
      if (!c->node)
	c->node = n;
      else
	_cdk_kbnode_add (c->node, n);

      switch (pkt->pkttype) 
	{
	case CDK_PKT_SYMKEY_ENC:
	  rc = handle_symkey_enc (c, hd, pkt);
	  _cdk_log_debug (" handle_symkey_enc = %d\n", rc);
	  break;
          
	case CDK_PKT_PUBKEY_ENC:
	  rc = handle_pubkey_enc (c, hd, pkt);
	  _cdk_log_debug (" handle_pubkey_enc  = %d\n", rc); 
	  break;
          
	case CDK_PKT_ENCRYPTED_MDC: 
	case CDK_PKT_ENCRYPTED:
	  rc = handle_encrypted (c, hd, pkt);
	  _cdk_log_debug (" handle_encrypted = %d\n", rc);
	  if (!rc)
	    inp = c->s;
	  break;
          
	case CDK_PKT_COMPRESSED:
	  if (!c->s)
	    c->s = inp;
	  rc = handle_compressed (c, pkt);
	  _cdk_log_debug (" handle_compressed = %d\n", rc);
	  break;
	  
	case CDK_PKT_ONEPASS_SIG:
	  if (!c->s)
	    c->s = inp;
	  _cdk_log_debug (" handle_onepass_sig = 0\n");
	  c->sig.present = 1;
	  c->sig.one_pass = 1;
	  c->sig.pt_offset = cdk_stream_tell (c->s);
	  break;
	  
	case CDK_PKT_LITERAL:
	  /* Multiple literal packets are not allowed. */
	  if (lit_seen)
	    {
	      _cdk_log_debug (" error: multiple literal packets\n");
	      return CDK_Inv_Packet;
	    }
	  
	  /* Skip rest of the packet */
	  if (!c->s)
	    c->s = inp;
	  if (!_cdk_stream_get_blockmode (c->s))
	    {
	      npos = cdk_stream_tell (c->s) + pkt->pkt.literal->len;
	      cdk_stream_seek (c->s, npos);
	    }
	  else
	    cdk_stream_seek (c->s, cdk_stream_get_length (c->s));
	  lit_seen = 1;
	  break;
          
	case CDK_PKT_SIGNATURE:
	  if (!c->sig.present)
	    c->sig.present = 1;
	  break; /* Handle it later */

	case CDK_PKT_MDC:
	  _cdk_log_debug ("MDC packet detected.\n");
	  break;
	  
	case CDK_PKT_MARKER:
	  _cdk_log_debug ("marker packet detected.\n");
	  break;
	  
	default:
	  _cdk_log_debug ("parse: invalid packet type=%d\n", pkt->pkttype);
	  return CDK_Inv_Packet;
        }
      if (rc)
	break;
    }
  if (c->eof_seen == 1)
    rc = 0;
  for (node = c->node; !rc && node; node = node->next)
    {
      pkt = node->pkt;
      switch (pkt->pkttype) 
	{
	case CDK_PKT_ONEPASS_SIG:
	  rc = handle_onepass_sig (c, pkt);
	  _cdk_log_debug (" _handle_onepass_sig = %d\n", rc);
	  break;
          
	case CDK_PKT_LITERAL:
	  rc = handle_literal (c, pkt, ret_out);
	  _cdk_log_debug (" _handle_literal  = %d\n", rc);
	  break;
	  
	case CDK_PKT_SIGNATURE:
	  rc = handle_signature (hd, c, pkt);
	  _cdk_log_debug (" _handle_signature  = %d\n", rc);
	  break;
	  
	case CDK_PKT_PUBKEY_ENC:
	case CDK_PKT_SYMKEY_ENC:
	case CDK_PKT_ENCRYPTED:
	case CDK_PKT_ENCRYPTED_MDC:
	case CDK_PKT_COMPRESSED:
	  /* No additional steps are needed, we just handle it to
	     detect invalid packets. */
	  break;
	  
	default:
	  _cdk_log_debug ("handle: invalid packet type = %d\n", pkt->pkttype);
	  return CDK_Inv_Packet;
        }
      if (rc)
	break;
    }
  if (rc == CDK_EOF)
    rc = CDK_Wrong_Seckey;
  return rc;
}


cdk_error_t
_cdk_proc_packets (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t datafp,
                   const char *output, cdk_stream_t outstream,
                   gcry_md_hd_t md)
{
  cdk_stream_t out = NULL;
  mainproc_ctx_t c;
  int rc;
  
  if (!inp)
    return CDK_Inv_Value;
  if (output && outstream)
    return CDK_Inv_Mode;

  c = cdk_calloc (1, sizeof *c);
  if (!c)
    return CDK_Out_Of_Core;
  if (output)
    c->output = output;
  if (outstream)
    c->tmpfp = outstream;
  if (datafp)
    c->datafp = datafp;
  if (md)
    c->sig.md = md;
  rc = do_proc_packets (hd, c, inp, &out);
  if (!c->tmpfp)
    cdk_stream_close (out);
  free_mainproc (c);
  return rc;
}
