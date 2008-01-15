/* keyserver.c - Simple keyserver support
 *        Copyright (C) 2002, 2003, 2007 Timo Schulz
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
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "opencdk.h"
#include "main.h"


static cdk_error_t
keyserver_hkp (const char *host, u16 port, u32 keyid, cdk_kbnode_t *ret_key)
{
  cdk_stream_t hkp, a;
  const char *fmt;
  char *buf, buffer[256];
  int state, nbytes;
  cdk_error_t rc;

  _cdk_log_debug ("keyserver_hkp: connect to `%s'\n", host);
  rc = cdk_stream_sockopen (host, port, &hkp);
  if (rc)
    return rc;
  
  fmt = "GET /pks/lookup?op=get&search=0x%08lX HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: close\r\n"
        "\r\n";
  buf = cdk_calloc (1, 64 + strlen (host) + strlen (fmt));
  if (!buf) 
    {
      cdk_stream_close (hkp);
      return CDK_Out_Of_Core;
    }
  sprintf (buf, fmt, keyid, host, port);
  
  nbytes = cdk_stream_write (hkp, buf, strlen (buf));
  cdk_free (buf);
  if (nbytes == -1) 
    {
      cdk_stream_close (hkp);
      return CDK_File_Error;
    }
  
  rc = cdk_stream_tmp_new (&a);
  if (rc) 
    {
      cdk_stream_close (hkp);
      return rc;
    }
  
  state = 0;
  do {	
    nbytes = cdk_stream_read (hkp, buffer, DIM (buffer)-1);
    if (nbytes < 1)
      break;
    buffer[nbytes] = '\0';
    cdk_stream_write (a, buffer, nbytes);
    if (strstr (buffer, "BEGIN PGP PUBLIC KEY") || 
	strstr (buffer, "END PGP PUBLIC KEY"))
      state++;
  } while (nbytes > 0);
  cdk_stream_close (hkp);
  
  if (state != 2)
    {
      _cdk_log_debug ("keyserver_hkp: incomplete key\n");
      cdk_stream_close (a);
      return CDK_Error_No_Key;
    }
  
  cdk_stream_tmp_set_mode (a, 0);
  cdk_stream_set_armor_flag (a, 0);
  cdk_stream_seek (a, 0);
  cdk_stream_read (a, NULL, 0);
  rc = cdk_keydb_get_keyblock (a, ret_key);
  cdk_stream_close (a);
  return rc;
}


const char*
skip_url_part (const char *host)
{
  const char *url_types[] = 
    {"http://", "hkp://", "x-hkp://", NULL};
  size_t i;
  
  for (i=0; url_types[i] != NULL; i++)
    {
      if (!strncmp (host, url_types[i], strlen (url_types[i])))
	{	    
	  host += strlen (url_types[i]);
	  break;
	}
    }  
  return host;
}

  

/**
 * cdk_keyserver_recv_key: 
 * @host: URL or hostname of the keyserver
 * @port: The port to use for the connection
 * @keyid: KeyID of the key to retrieve
 * @kid_type: KeyID type (long, short, fingerprint)
 * @r_knode: The key that was found wrapped in a KBNODE struct
 *
 * Receive a key from a keyserver.
 **/
cdk_error_t
cdk_keyserver_recv_key (const char *host, int port,
                        const byte *keyid, int kid_type,
                        cdk_kbnode_t *ret_key)
{
  u32 kid;
  
  if (!host || !keyid || !ret_key)
    return CDK_Inv_Value;
  
  if (!port)
    port = 11371;

  host = skip_url_part (host);
  
  switch (kid_type) 
    {
    case CDK_DBSEARCH_SHORT_KEYID:
      kid = _cdk_buftou32 (keyid);
      break;
      
    case CDK_DBSEARCH_KEYID:
      kid = _cdk_buftou32 (keyid + 4); 
      break;
    case CDK_DBSEARCH_FPR:
      kid = _cdk_buftou32 (keyid + 16);
      break;
    default:
      return CDK_Inv_Mode;
    }
  
  return keyserver_hkp (host, port, kid, ret_key);
}
