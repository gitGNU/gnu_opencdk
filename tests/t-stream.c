/* t-stream.c
 *        Copyright (C) 2002, 2007 Timo Schulz
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
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenCDK; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "opencdk.h"
#include "t-support.h"

static int err_cnt = 0;


static cdk_error_t basic (void)
{
  cdk_stream_t inp;
  cdk_error_t err;
  size_t i;
  int c;
  
  err = cdk_stream_open (make_filename ("plain-test-cs.asc"), &inp);
  if (err)
    return err;
  for (i=0; i < 5; i++)
    {
      c = cdk_stream_getc (inp);
      if (c != '-')
	{
	  cdk_stream_close (inp);
	  return CDK_Inv_Value;
	}
    }
  cdk_stream_seek (inp, 0);
  if (cdk_stream_getc (inp) != '-' || cdk_stream_tell (inp) != 1)
    {
      cdk_stream_close (inp);
      return CDK_Inv_Value;
    }
  
  if (cdk_stream_get_length (inp) == 0)
    {
      cdk_stream_close (inp);
      return CDK_Inv_Value;
    }    
  
  cdk_stream_close (inp);
  return err;
}

static cdk_error_t temp (void)
{
  cdk_stream_t tmp;
  cdk_error_t err;
  char buf[32];
  int n;
  off_t len;
  
  err = cdk_stream_tmp_new (&tmp);
  if (err)
    return err;
  n = cdk_stream_write (tmp, "test", 4);
  if (!n || n == -1)
    {
      cdk_stream_close (tmp);
      return CDK_Inv_Value;
    } 
  len = cdk_stream_get_length (tmp);
  if (len != 4)
    {
      cdk_stream_close (tmp);
      return CDK_Inv_Value;
    }
  
  cdk_stream_seek (tmp, 0);
  n = cdk_stream_read (tmp, buf, 4);
  if (n != 4 || memcmp (buf, "test", 4))
    err = CDK_Inv_Value;
  
  cdk_stream_close (tmp);
  return err;
}


static void stream_tests (void)
{
  cdk_error_t err;
  
  err = basic ();
  if (err)
    {
      fprintf (stderr, "%s:%d basic FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
  err = temp ();
  if (err)
    {
      fprintf (stderr, "%s:%d temp FAILED\n", __FILE__, __LINE__);
      err_cnt++;
    }
}


int main (int argc, char **argv)
{
  stream_tests ();
  return err_cnt;
}
