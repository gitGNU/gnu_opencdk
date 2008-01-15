/* stream-socket.c - Socket callback for stream
 *        Copyright (C) 2007 Timo Schulz
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
#include <stdio.h>
#include <gcrypt.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include "opencdk.h"
#include "types.h"
#include "filters.h"
#include "stream.h"
#include "main.h"


/* Under Windows close cannot be used to close a socket. */
#ifdef _WIN32
#define _sock_fd_close closesocket
#else
#define _sock_fd_close close
#endif


struct stream_sock_cb_s
{
  char *host;
  unsigned short port;
  int fd;
};
typedef struct stream_sock_cb_s *stream_sock_cb_t;


/* This function will connect the socket. */
cdk_error_t
sock_open (void *ctx)
{
  struct hostent *hp;
  struct sockaddr_in saddr;
  stream_sock_cb_t cb = (stream_sock_cb_t)ctx;
  
  /* FIXME: [W32] we need to check if @host is actually a dotted IP */
  hp = gethostbyname (cb->host);
  if (!hp)
    return CDK_Network_Error;
  
  memset (&saddr, 0, sizeof (saddr));
  memcpy (&saddr.sin_addr, hp->h_addr, hp->h_length);
  saddr.sin_family = hp->h_addrtype;
  saddr.sin_port = htons (cb->port);
  
  cb->fd = socket (AF_INET, SOCK_STREAM, 0);
  _cdk_log_debug ("sock_open: open socket fd=%d\n", cb->fd);
  if (cb->fd == -1)
    return CDK_General_Error;
  
  setsockopt (cb->fd, SOL_SOCKET, SO_REUSEADDR, (char *)1, 1);
  if (connect (cb->fd, (struct sockaddr *) &saddr, sizeof (saddr)) == -1) 
    {
      _cdk_log_debug ("sock_open: connect failed\n");
      _sock_fd_close (cb->fd); cb->fd = -1;
      return CDK_Network_Error;
    }
  return 0;
}


/* The release function will be close the socket and
   free the context structure. */
cdk_error_t
sock_release (void *ctx)
{
  stream_sock_cb_t cb = (stream_sock_cb_t)ctx;
  
  if (!cb)
    return CDK_Inv_Value;
  
  if (cb->fd != -1)
    {
      _cdk_log_debug ("sock_release: close socket fd=%d\n", cb->fd);
      _sock_fd_close (cb->fd);
    }  
  cb->fd = -1;
  cdk_free (cb->host);
  cdk_free (cb);
  
  return 0;
}


/* Read @buflen bytes from the associated socket. */
int
sock_read (void *ctx, void *buf, size_t buflen)
{
  stream_sock_cb_t cb = (stream_sock_cb_t)ctx;
  
  return recv (cb->fd, buf, buflen, 0);
}


/* Write @buflen bytes from the associated socket. */
int
sock_write (void *ctx, const void *buf, size_t buflen)
{
  stream_sock_cb_t cb = (stream_sock_cb_t)ctx;
  
  return send (cb->fd, buf, buflen, 0);
}


/**
 * cdk_stream_sockopen:
 * @host: the host to connect to
 * @port: the port to use
 * @ret_out: contains the connect stream.
 * 
 * Connect a stream to the given host:port pair.
 **/
cdk_error_t
cdk_stream_sockopen (const char *host, unsigned short port, 
		     cdk_stream_t *ret_out)
{
  stream_sock_cb_t cb;
  struct cdk_stream_cbs_s cbs;
  
  cb = calloc (1, sizeof *cb);
  if (!cb)
    return CDK_Out_Of_Core;
  cb->host = cdk_strdup (host);
  cb->port = port;
  
  memset (&cbs, 0, sizeof (cbs));
  cbs.open = sock_open;
  cbs.release = sock_release;
  cbs.read = sock_read;
  cbs.write = sock_write;
  return cdk_stream_new_from_cbs (&cbs, (void*)cb, ret_out);
}
