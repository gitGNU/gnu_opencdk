/* write-cipher.c - openpgp cipher writer
 *       Copyright (C) 2007 Timo Schulz
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

#include "opencdk.h"
#include "main.h"
#include "new-io.h"


/* Cipher writer context. */
struct cipher_writer_s
{
  int header_written;
  int use_mdc;
  cdk_dek_t dek;
  gcry_cipher_hd_t hd;
  gcry_md_hd_t mdc;
  unsigned char rndpref[18]; /* random prefix (iv replacement) */
  size_t blklen;             /* block size of the buffer. */
  unsigned char *buffer;     /* to store parts of the input buffer. */
  size_t bufsize;
  size_t restlen;
  int error;
};


/* Helper to return the amount of bits needed to encode the value n. */
static __inline__ int
num2bits (size_t n)
{
  size_t i;
  
  for (i = 0; n > 1; i++)
    n >>= 1;
  return i;
}


/* Helper to emulate fputc like functionality. */
static int
writer_next_putc (cdk_writer_t wr, int c)
{
  unsigned char buf[1];
  
  buf[0] = c;
  return _cdk_writer_write_next (wr, buf, 1) < 0? -1 : 0;
}


/* Encode the packet size in a valid packet header.
   We use the partial body length to encode chunks. */
static int
write_packet_header (cdk_writer_t wr, size_t nbits, size_t buflen)
{
  /* No buffer length were given, so use partial body length. */
  if (!buflen)
    return writer_next_putc (wr, 0xE0|nbits);
  
  /* As per openpgp standard, the last packet shall be encoded in
     normal length mode. */
  if (buflen < 192)
    return writer_next_putc (wr, buflen);
  else if (buflen < 8383)
    {
      buflen -= 192;
      writer_next_putc (wr,  (buflen / 256) + 192);
      writer_next_putc (wr, buflen % 256);
    }
  else
    {
      writer_next_putc (wr, 0xFF);
      writer_next_putc (wr, buflen >> 24);
      writer_next_putc (wr, buflen >> 16);
      writer_next_putc (wr, buflen >>  8);
      writer_next_putc (wr, buflen >>  0);
    }
  
  return 0;
}
      

/* Encrypt the given buffer and pass it to the next writer. */
static int
cipher_write (cdk_writer_t wr, void *ctx, const void *buf, size_t buflen)
{
  cipher_writer_t enc = (cipher_writer_t)ctx;
  const unsigned char *inbuf;
  size_t nbits, ninbytes, blksize;
  
  if (enc->error)
    return -1;
  
  /* It may happen that we need to store the rest of the block in the
     buffer and this is only possible without an overflow if the buffer
     fits in the writer buffer. */
  if (buflen > enc->bufsize)
    return -1;
  
  if (!enc->header_written)
    {
      int pkttype = enc->use_mdc? CDK_PKT_ENCRYPTED_MDC : CDK_PKT_ENCRYPTED;
      size_t pktlen;
      
      writer_next_putc (wr, 0xC0|pkttype);
      pktlen = buflen + enc->blklen + 2 + enc->restlen;
      if (enc->use_mdc)
	pktlen++; /* 1 octet version. */
      nbits = num2bits (pktlen);
      blksize = (1 << nbits);
      enc->error = write_packet_header (wr, nbits, 0);
      if (enc->error)
	return -1;
      if (enc->use_mdc)
	{	  
	  writer_next_putc (wr, 1); /* Version */
	  blksize--;
	}      
      _cdk_writer_write_next (wr, enc->rndpref, enc->blklen + 2);
      blksize -= (enc->blklen+2);
      enc->header_written = 1;
    }
  else
    {
      nbits = num2bits (buflen + enc->restlen);
      blksize = (1 << nbits);
      enc->error = write_packet_header (wr, nbits, 0);
      if (enc->error)
	return -1;
    }  
  
  if (enc->use_mdc) /* Update the digest with the buffer contents. */
    gcry_md_write (enc->mdc, buf, buflen);
  
  /* Flush the old pending buffer contents. */
  if (enc->restlen > 0)
    {
      _cdk_log_debug ("cipher_write: flush rest %d octets\n", enc->restlen);
      gcry_cipher_encrypt (enc->hd, enc->buffer, enc->restlen, NULL, 0);
      _cdk_writer_write_next (wr, enc->buffer, enc->restlen);
      blksize -= enc->restlen;
    }
  
  inbuf = (const unsigned char*)buf;  
  while (blksize > 0)
    {
      if (blksize >  enc->bufsize)
	ninbytes = enc->bufsize;
      else
	ninbytes = blksize;      
      memcpy (enc->buffer, inbuf, ninbytes);
      inbuf += ninbytes;

      enc->error = gcry_cipher_encrypt (enc->hd, enc->buffer, 
					ninbytes, NULL, 0);
      if (enc->error)
	return -1;      
      _cdk_writer_write_next (wr, enc->buffer, ninbytes);
      blksize -= ninbytes;
      buflen -= ninbytes;
      _cdk_log_debug ("cipher_write: out %d octets rest %d\n",
		      ninbytes, blksize);
    }

  enc->restlen = buflen;
  if (enc->restlen > 0)
    { 
      /* Now store the remaining part of the buffer buflen - 2^N. */
      memcpy (enc->buffer, inbuf, enc->restlen);
      _cdk_log_debug ("cipher_write: restlen %d\n", enc->restlen);
    }  
  
  return 0;
}
  


/* Write the MDC packet to the next writer. */
static int
write_mdc_packet (cdk_writer_t wr, cipher_writer_t enc)
{
  unsigned char pktdata[22];
  
  _cdk_log_debug ("write_mdc_packet: flush\n");
  /* We must hash the prefix of the MDC packet here */
  pktdata[0] = 0xD3;
  pktdata[1] = 0x14;
  gcry_md_write (enc->mdc, pktdata, 2);
  gcry_md_final (enc->mdc);
  memcpy (pktdata + 2, gcry_md_read (enc->mdc, GCRY_MD_SHA1), 20);
  gcry_cipher_encrypt (enc->hd, pktdata, 22, NULL, 0);
  _cdk_writer_write_next (wr, pktdata, 22);
  wipemem (pktdata, sizeof (pktdata));
  
  return 0;
}


/* Flush the encryption buffer. */
static int
cipher_flush (cdk_writer_t wr)
{
  cipher_writer_t enc = (cipher_writer_t)cdk_writer_get_opaque (wr);
  size_t nout;

  _cdk_log_debug ("cipher_flush: flush %d octets (mdc %d)\n",
		  enc->restlen, enc->use_mdc);
  
  if (enc->restlen > 0)
    {      
      /* If the are still pending bytes, we need to flush them now
       and include the size of the MDC packet if the MDC feature is used. */
      nout = (enc->use_mdc? 22 : 0) + enc->restlen;
      
      /* The last chunk of data is not encoded via the partial mode to
       indicate that the next packet is the last in the stream. */
      write_packet_header (wr, 0, nout);
      
      enc->error = gcry_cipher_encrypt (enc->hd, enc->buffer, enc->restlen,
					NULL, 0);
      if (enc->error)
	return -1;
      _cdk_writer_write_next (wr, enc->buffer, enc->restlen);
      enc->restlen = 0;
    }
  
  if (enc->use_mdc)
    enc->error = write_mdc_packet (wr, enc);  
  return enc->error? -1 : 0;
}


/* Release the cipher context. */
static int
cipher_release (void *ctx)
{
  cipher_writer_t enc = (cipher_writer_t)ctx;
  
  if (enc->hd != NULL)
    gcry_cipher_close (enc->hd);
  if (enc->mdc != NULL)
    gcry_md_close (enc->mdc);
  wipemem (enc->buffer, enc->bufsize);
  cdk_free (enc->buffer);
  cdk_free (enc);
  
  return 0;
}


/* Init the cipher context. */
static int
cipher_init (void **r_ctx)
{
  cipher_writer_t enc;
  
  enc = cdk_calloc (1, sizeof *enc);
  if (!enc)
    return CDK_Out_Of_Core;
  *r_ctx = enc;
  return 0;
}


/* Allocate a new cipher writer with the given buffer size. */
cdk_error_t
cipher_writer_new (cipher_writer_t *r_enc, size_t bufsize)
{
  cipher_writer_t enc;
  cdk_error_t err;
  void *ctx;
  
  if (!r_enc || bufsize < 512)
    return CDK_Inv_Value;
  
  *r_enc = NULL;
  err = cipher_init (&ctx);
  if (err)
    return err;
  enc = (cipher_writer_t)ctx;
  enc->bufsize = bufsize;
  enc->buffer = cdk_calloc (1, bufsize);
  if (!enc->buffer)
    {  
      cdk_free (enc);
      return CDK_Out_Of_Core;
    }  
  *r_enc = enc;
  
  return 0;
}


/* Associate a data encryption key (DEK) with the given writer. */
cdk_error_t
cipher_writer_set_dek (cipher_writer_t enc, cdk_dek_t dek)
{
  gcry_error_t err;
  int algo;
  
  if (!enc || !dek)
    return CDK_Inv_Value;

  /* Make sure the cipher has a valid block size. */
  cdk_dek_get_cipher (dek, &algo);
  enc->blklen = gcry_cipher_get_algo_blklen (algo);
  if (enc->blklen != 8 && enc->blklen != 16)
    return CDK_Inv_Algo;
  
  /* For old 64-bit ciphers, we reset the MDC mode. */
  enc->use_mdc = cdk_dek_get_mdc_flag (dek);
  if (enc->blklen == 8)    
    enc->use_mdc = 0;
  
  if (enc->use_mdc)
    {
      if (enc->mdc != NULL)
	gcry_md_close (enc->mdc);
      err = gcry_md_open (&enc->mdc, GCRY_MD_SHA1, 0);
      if (err)
	return map_gcry_error (err);
    }
  
  /* Create the random prefix which is used by OpenPGP instead
     of the IV for the CFB mode. */
  gcry_randomize (enc->rndpref, enc->blklen, GCRY_STRONG_RANDOM);
  enc->rndpref[enc->blklen] = enc->rndpref[enc->blklen - 2];
  enc->rndpref[enc->blklen + 1] = enc->rndpref[enc->blklen - 1];
  
  err = gcry_cipher_open (&enc->hd, algo, GCRY_CIPHER_MODE_CFB,
			  enc->use_mdc? 0 : GCRY_CIPHER_ENABLE_SYNC);
  if (err)
    return map_gcry_error (err);
  err = gcry_cipher_setiv (enc->hd, NULL, 0);
  if (err)
    return map_gcry_error (err);
  
  /* FIXME: The nio module should not know about any internals of
            the DEK structure. */
  err = gcry_cipher_setkey (enc->hd, dek->key, dek->keylen);
  if (err)
    return map_gcry_error (err);
  if (enc->use_mdc)
    gcry_md_write (enc->mdc, enc->rndpref, enc->blklen + 2);
  gcry_cipher_encrypt (enc->hd, enc->rndpref, enc->blklen + 2, NULL, 0);
  gcry_cipher_sync (enc->hd);
  
  return 0;
}


/**
 * cdk_writer_cipher_new:
 * @r_wr: store the new allocated writer object
 * @next: next writer in the chain
 * @enc: the cipher context
 * 
 * Return a new allocated writer with cipher callback functions. 
 **/
cdk_error_t
cdk_writer_cipher_new (cdk_writer_t *r_wr, cdk_writer_t next,
		       cipher_writer_t enc)
{
  return cdk_writer_new (r_wr, next, &cipher_writer, enc);
}


/* Module handle for the cipher functions. */
struct cdk_writer_cbs_s cipher_writer =
{cipher_write, cipher_flush, cipher_release, cipher_init};
