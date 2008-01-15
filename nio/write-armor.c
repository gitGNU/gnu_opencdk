/* write-armor.c
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

/* base64_encode based on the fetchmail version written by Eric Raymond. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "opencdk.h"
#include "main.h"
#include "new-io.h"


#ifdef __MINGW32__
# define LF "\r\n"
#else
# define LF "\n"
#endif

#define CRCINIT 0xB704CE

static unsigned int crc_table[] = {
0x000000, 0x864CFB, 0x8AD50D, 0x0C99F6, 0x93E6E1, 0x15AA1A, 0x1933EC, 0x9F7F17,
0xA18139, 0x27CDC2, 0x2B5434, 0xAD18CF, 0x3267D8, 0xB42B23, 0xB8B2D5, 0x3EFE2E,
0xC54E89, 0x430272, 0x4F9B84, 0xC9D77F, 0x56A868, 0xD0E493, 0xDC7D65, 0x5A319E,
0x64CFB0, 0xE2834B, 0xEE1ABD, 0x685646, 0xF72951, 0x7165AA, 0x7DFC5C, 0xFBB0A7,
0x0CD1E9, 0x8A9D12, 0x8604E4, 0x00481F, 0x9F3708, 0x197BF3, 0x15E205, 0x93AEFE,
0xAD50D0, 0x2B1C2B, 0x2785DD, 0xA1C926, 0x3EB631, 0xB8FACA, 0xB4633C, 0x322FC7,
0xC99F60, 0x4FD39B, 0x434A6D, 0xC50696, 0x5A7981, 0xDC357A, 0xD0AC8C, 0x56E077,
0x681E59, 0xEE52A2, 0xE2CB54, 0x6487AF, 0xFBF8B8, 0x7DB443, 0x712DB5, 0xF7614E,
0x19A3D2, 0x9FEF29, 0x9376DF, 0x153A24, 0x8A4533, 0x0C09C8, 0x00903E, 0x86DCC5,
0xB822EB, 0x3E6E10, 0x32F7E6, 0xB4BB1D, 0x2BC40A, 0xAD88F1, 0xA11107, 0x275DFC,
0xDCED5B, 0x5AA1A0, 0x563856, 0xD074AD, 0x4F0BBA, 0xC94741, 0xC5DEB7, 0x43924C,
0x7D6C62, 0xFB2099, 0xF7B96F, 0x71F594, 0xEE8A83, 0x68C678, 0x645F8E, 0xE21375,
0x15723B, 0x933EC0, 0x9FA736, 0x19EBCD, 0x8694DA, 0x00D821, 0x0C41D7, 0x8A0D2C,
0xB4F302, 0x32BFF9, 0x3E260F, 0xB86AF4, 0x2715E3, 0xA15918, 0xADC0EE, 0x2B8C15,
0xD03CB2, 0x567049, 0x5AE9BF, 0xDCA544, 0x43DA53, 0xC596A8, 0xC90F5E, 0x4F43A5,
0x71BD8B, 0xF7F170, 0xFB6886, 0x7D247D, 0xE25B6A, 0x641791, 0x688E67, 0xEEC29C,
0x3347A4, 0xB50B5F, 0xB992A9, 0x3FDE52, 0xA0A145, 0x26EDBE, 0x2A7448, 0xAC38B3,
0x92C69D, 0x148A66, 0x181390, 0x9E5F6B, 0x01207C, 0x876C87, 0x8BF571, 0x0DB98A,
0xF6092D, 0x7045D6, 0x7CDC20, 0xFA90DB, 0x65EFCC, 0xE3A337, 0xEF3AC1, 0x69763A,
0x578814, 0xD1C4EF, 0xDD5D19, 0x5B11E2, 0xC46EF5, 0x42220E, 0x4EBBF8, 0xC8F703,
0x3F964D, 0xB9DAB6, 0xB54340, 0x330FBB, 0xAC70AC, 0x2A3C57, 0x26A5A1, 0xA0E95A,
0x9E1774, 0x185B8F, 0x14C279, 0x928E82, 0x0DF195, 0x8BBD6E, 0x872498, 0x016863,
0xFAD8C4, 0x7C943F, 0x700DC9, 0xF64132, 0x693E25, 0xEF72DE, 0xE3EB28, 0x65A7D3,
0x5B59FD, 0xDD1506, 0xD18CF0, 0x57C00B, 0xC8BF1C, 0x4EF3E7, 0x426A11, 0xC426EA,
0x2AE476, 0xACA88D, 0xA0317B, 0x267D80, 0xB90297, 0x3F4E6C, 0x33D79A, 0xB59B61,
0x8B654F, 0x0D29B4, 0x01B042, 0x87FCB9, 0x1883AE, 0x9ECF55, 0x9256A3, 0x141A58,
0xEFAAFF, 0x69E604, 0x657FF2, 0xE33309, 0x7C4C1E, 0xFA00E5, 0xF69913, 0x70D5E8,
0x4E2BC6, 0xC8673D, 0xC4FECB, 0x42B230, 0xDDCD27, 0x5B81DC, 0x57182A, 0xD154D1,
0x26359F, 0xA07964, 0xACE092, 0x2AAC69, 0xB5D37E, 0x339F85, 0x3F0673, 0xB94A88,
0x87B4A6, 0x01F85D, 0x0D61AB, 0x8B2D50, 0x145247, 0x921EBC, 0x9E874A, 0x18CBB1,
0xE37B16, 0x6537ED, 0x69AE1B, 0xEFE2E0, 0x709DF7, 0xF6D10C, 0xFA48FA, 0x7C0401,
0x42FA2F, 0xC4B6D4, 0xC82F22, 0x4E63D9, 0xD11CCE, 0x575035, 0x5BC9C3, 0xDD8538 
};

static const char *armor_begin[] = {
    "BEGIN PGP MESSAGE",
    "BEGIN PGP PUBLIC KEY BLOCK",
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PGP SIGNATURE",
    NULL
};

static const char *armor_end[] = {
    "END PGP MESSAGE",
    "END PGP PUBLIC KEY BLOCK",
    "END PGP PRIVATE KEY BLOCK",
    "END PGP SIGNATURE",
    NULL
};


static char b64chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/* encode a raw binary buffer to a null-terminated base64 strings */
static int
base64_encode (char *out, const unsigned char *in, size_t len, size_t olen)
{
  if (!out || !in)
    return CDK_Inv_Value;
  
  while (len >= 3 && olen > 10)
    {    
      *out++ = b64chars[in[0] >> 2];
      *out++ = b64chars[((in[0] << 4) & 0x30) | (in[1] >> 4)];
      *out++ = b64chars[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
      *out++ = b64chars[in[2] & 0x3f];
      olen -= 4;
      len -= 3;
      in += 3;
    }
  
  /* clean up remainder */
  if (len > 0 && olen > 4)
    {
      unsigned char fragment = 0;
      
      *out++ = b64chars[in[0] >> 2];
      fragment = (in[0] << 4) & 0x30;
      if (len > 1)
	fragment |= in[1] >> 4;
      *out++ = b64chars[fragment];
      *out++ = (len < 2) ? '=' : b64chars[(in[1] << 2) & 0x3c];
      *out++ = '=';
    }
  *out = '\0';
  return 0;
}


static unsigned int
update_crc (unsigned int crc, const unsigned char *buf, size_t buflen)
{
  int j;
  
  if (!crc)
    crc = CRCINIT;
  
  for (j = 0; j < buflen; j++)
    crc = (crc << 8) ^ crc_table[0xff & ((crc >> 16) ^ buf[j])];
  crc &= 0xffffff;
  return crc;
}


/* Armor writer context. */
struct armor_writer_s
{
  unsigned int crc;
  int msg_type;
  int head_written;
  unsigned char rest[2*48];
  size_t restlen;
  size_t outwritten;
};



/* Write the remaining data of a block to the writer.
   This can be happen because not all file sizes are a multiple of
   three, plus we write packet headers and other fixed buffers. */
static int
armor_write_rest (cdk_writer_t w, armor_writer_t a)
{
  const char *p;
  char buffer[256];
  size_t outlen;
  
  /* For the last block it is possible that we need to break
     the data into two lines. */
  /*fprintf (stderr, "armor: write rest %d bytes\n", a->restlen);*/
  a->crc = update_crc (a->crc, a->rest, a->restlen);
  base64_encode (buffer, a->rest, a->restlen, 128);
  p = buffer;
  outlen = strlen (buffer);
  if (outlen > 64)
    {
      _cdk_writer_write_next (w, p, 64);
      _cdk_writer_write_next (w, LF, strlen (LF));
      outlen -= 64;
      p += 64;
    }
  _cdk_writer_write_next (w, p, outlen);
  _cdk_writer_write_next (w, LF, strlen (LF));
  a->restlen = 0;
  
  return 0;
}


/* Encode a block of data with armor. */
static int
armor_write (cdk_writer_t wr, void *ctx, const void *buf, size_t buflen)
{
  armor_writer_t a = (armor_writer_t)ctx;
  char buffer[128];
  const unsigned char *inbuf = buf;
  size_t off;

  if (!a->head_written)
    {
      const char *s;
      
      _cdk_log_debug ("armor_write: head %d\n", a->msg_type);
      _cdk_writer_write_next (wr, "-----", 5);
      s = armor_begin[a->msg_type];
      _cdk_writer_write_next (wr, s, strlen (s));
      _cdk_writer_write_next (wr, "-----", 5);
      _cdk_writer_write_next (wr, LF, strlen (LF));
      /* Empty line to separate headers and data. */
      _cdk_writer_write_next (wr, LF, strlen (LF));
      a->head_written = 1;
    }  
  
  if (a->restlen > 0 && buflen >= 48)
    {
      size_t nsteal = 48 - a->restlen;
      
      memcpy (a->rest + a->restlen, inbuf, nsteal);
      inbuf += nsteal;
      buflen -= nsteal;
      a->restlen = 48;
      armor_write_rest (wr, a);
    }  
  
  for (off = 0; buflen >= 48;)
    {
      a->crc = update_crc (a->crc, inbuf + off, 48);
      base64_encode (buffer, inbuf + off, 48, 128);
      _cdk_writer_write_next (wr, buffer, strlen (buffer));
      _cdk_writer_write_next (wr, LF, strlen (LF));
      off += 48;
      buflen -= 48;
      a->outwritten += 48;
    }

  if (buflen > 0)
    { 
      memcpy (a->rest + a->restlen, inbuf + off, buflen);
      _cdk_log_debug ("armor: store %d remaining bytes rest %d\n",
		      buflen, a->restlen);
      a->restlen += buflen;
    }
  
  return 0;
}


/* Flush the armor filter. This will write pending bytes and
   complete the armor wrapper. */
static int
armor_flush (cdk_writer_t wr)
{
  armor_writer_t a = (armor_writer_t)cdk_writer_get_opaque (wr);
  char crcbuf[5];
  unsigned char crcbuf2[3];
  
  _cdk_log_debug ("armor_flush: msg type %d\n", a->msg_type);
  
  if (!a->outwritten)
    return 0;
  
  if (a->restlen > 0)
    armor_write_rest (wr, a);
  
  crcbuf2[0] = a->crc >> 16;
  crcbuf2[1] = a->crc >> 8;
  crcbuf2[2] = a->crc;
  crcbuf[0] = b64chars[crcbuf2[0] >> 2];
  crcbuf[1] = b64chars[((crcbuf2[0] << 4) & 0x30) |(crcbuf2[1] >> 4)];
  crcbuf[2] = b64chars[((crcbuf2[1] << 2) & 0x3c) |(crcbuf2[2] >> 6)];
  crcbuf[3] = b64chars[crcbuf2[2] & 0x3f];
  _cdk_writer_write_next (wr, "=", 1);
  _cdk_writer_write_next (wr, crcbuf, 4);
  _cdk_writer_write_next (wr, LF, strlen (LF));
  _cdk_writer_write_next (wr, "-----", 5);
  _cdk_writer_write_next (wr, armor_end[a->msg_type], strlen (armor_end[a->msg_type]));
  _cdk_writer_write_next (wr, "-----", 5);
  _cdk_writer_write_next (wr, LF, strlen (LF));
  
  return 0;
}


/* Close the armor writer and cleanup. */
static int
armor_release (void *ctx)
{
  armor_writer_t a = (armor_writer_t)ctx;
  
  _cdk_log_debug ("armor_close: msg type %d\n", a->msg_type);
  a->msg_type = 0;
  cdk_free (a);
  
  return 0;
}


/* Allocate new armor context. */
static int
armor_init (void **r_ctx)
{
  armor_writer_t a;
  
  a = cdk_calloc (1, sizeof *a);
  if (!a)
    return CDK_Out_Of_Core;
  a->msg_type = 0;
  *r_ctx = a;
  return 0;
}


cdk_error_t
armor_writer_new (armor_writer_t *r_arm, int msg_type)
{
  void *arm;
  cdk_error_t err;
  
  *r_arm = NULL;  
  err = armor_init (&arm);
  if (err)
    return err;

  err = armor_writer_set_msg_type ((armor_writer_t)arm, msg_type);
  if (err)
    {
      armor_release (arm);
      return err;
    }
  
  *r_arm = (armor_writer_t)arm;
  return 0;
}

  
cdk_error_t
armor_writer_set_msg_type (armor_writer_t arm, int msg_type)
{
  arm->msg_type = msg_type;
  return 0;
}


cdk_error_t
cdk_writer_armor_new (cdk_writer_t *r_wr, cdk_writer_t next,
		      armor_writer_t arm)
{
  return cdk_writer_new (r_wr, next, &armor_writer, arm);
}


struct cdk_writer_cbs_s armor_writer =
{armor_write, armor_flush, armor_release, armor_init};
