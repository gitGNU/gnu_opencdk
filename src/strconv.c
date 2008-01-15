/* strconv.c
 *        Copyright (C) 2002, 2003 Timo Schulz
 *        Copyright (C) 1998-2002, 2007 Free Software Foundation, Inc.
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
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "main.h"

/**
 * cdk_utf8_encode:
 * @string:
 * 
 * Encode the given string in utf8 and return it.
 **/
char*
cdk_utf8_encode (const char *string)
{
  const byte *s;
  char *buffer;
  byte *p;
  size_t length;
  
  /* FIXME: We should use iconv if possible for utf8 issues. */
  for (s = (const byte*)string, length = 0; *s; s++) 
    {
      length++;
      if (*s & 0x80)
	length++;
    }

    buffer = cdk_calloc (1, length + 1);
    for (p = (byte*)buffer, s = (byte*)string; *s; s++) 
    {
      if (*s & 0x80) 
	{
	  *p++ = 0xc0 | ((*s >> 6) & 3);
	  *p++ = 0x80 | (*s & 0x3f);
        }
      else
	*p++ = *s;
    }
  *p = 0;
  return buffer;
}


/**
 * cdk_utf8_decode:
 * @string: the string to decode
 * @length: the length of the string
 * @delim: the delimiter
 *
 * Decode the given utf8 string and return the native representation.
 **/
char *
cdk_utf8_decode (const char * string, size_t length, int delim)
{
  int nleft;
  int i;
  byte encbuf[8];
  int encidx;
  const byte *s;
  size_t n;
  byte *buffer = NULL, *p = NULL;
  unsigned long val = 0;
  size_t slen;
  int resync = 0;

  /* 1. pass (p==NULL): count the extended utf-8 characters */
  /* 2. pass (p!=NULL): create string */
  for (;;)
    {
      for (slen = length, nleft = encidx = 0, n = 0, s = (byte*)string; slen;
           s++, slen--)
	{
          if (resync)
	    {
              if (!(*s < 128 || (*s >= 0xc0 && *s <= 0xfd)))
		{
                  /* still invalid */
                  if (p)
		    {
                      sprintf ((char*)p, "\\x%02x", *s);
                      p += 4;
		    }
                  n += 4;
                  continue;
		}
              resync = 0;
	    }
          if (!nleft)
	    {
              if (!(*s & 0x80))
		{		/* plain ascii */
                  if (*s < 0x20 || *s == 0x7f || *s == delim ||
                      (delim && *s == '\\'))
		    {
                      n++;
                      if (p)
                        *p++ = '\\';
                      switch (*s)
			{
			case '\n':
                          n++;
                          if (p)
                            *p++ = 'n';
                          break;
			case '\r':
                          n++;
                          if (p)
                            *p++ = 'r';
                          break;
			case '\f':
                          n++;
                          if (p)
                            *p++ = 'f';
                          break;
			case '\v':
                          n++;
                          if (p)
                            *p++ = 'v';
                          break;
			case '\b':
                          n++;
                          if (p)
                            *p++ = 'b';
                          break;
			case 0:
                          n++;
                          if (p)
                            *p++ = '0';
                          break;
			default:
                          n += 3;
                          if (p)
			    {
                              sprintf ((char*)p, "x%02x", *s);
                              p += 3;
			    }
                          break;
			}
		    }
                  else
		    {
                      if (p)
                        *p++ = *s;
                      n++;
		    }
		}
              else if ((*s & 0xe0) == 0xc0)
		{		/* 110x xxxx */
                  val = *s & 0x1f;
                  nleft = 1;
                  encidx = 0;
                  encbuf[encidx++] = *s;
		}
              else if ((*s & 0xf0) == 0xe0)
		{		/* 1110 xxxx */
                  val = *s & 0x0f;
                  nleft = 2;
                  encidx = 0;
                  encbuf[encidx++] = *s;
		}
              else if ((*s & 0xf8) == 0xf0)
		{		/* 1111 0xxx */
                  val = *s & 0x07;
                  nleft = 3;
                  encidx = 0;
                  encbuf[encidx++] = *s;
		}
              else if ((*s & 0xfc) == 0xf8)
		{		/* 1111 10xx */
                  val = *s & 0x03;
                  nleft = 4;
                  encidx = 0;
                  encbuf[encidx++] = *s;
		}
              else if ((*s & 0xfe) == 0xfc)
		{		/* 1111 110x */
                  val = *s & 0x01;
                  nleft = 5;
                  encidx = 0;
                  encbuf[encidx++] = *s;
		}
              else
		{		/* invalid encoding: print as \xnn */
                  if (p)
		    {
                      sprintf ((char*)p, "\\x%02x", *s);
                      p += 4;
		    }
                  n += 4;
                  resync = 1;
		}
	    }
          else if (*s < 0x80 || *s >= 0xc0)
	    {			/* invalid */
              if (p)
		{
                  for (i = 0; i < encidx; i++)
		    {
                      sprintf ((char*)p, "\\x%02x", encbuf[i]);
                      p += 4;
		    }
                  sprintf ((char*)p, "\\x%02x", *s);
                  p += 4;
		}
              n += 4 + 4 * encidx;
              nleft = 0;
              encidx = 0;
              resync = 1;
	    }
          else
	    {
              encbuf[encidx++] = *s;
              val <<= 6;
              val |= *s & 0x3f;
              if (!--nleft)
		{ /* ready native set */
                  if (val >= 0x80 && val < 256)
                    {
                      n++;	/* we can simply print this character */
                      if (p)
                        *p++ = val;
                    }
                  else
                    {	/* we do not have a translation: print utf8 */
                      if (p)
                        {
                          for (i = 0; i < encidx; i++)
                            {
                              sprintf ((char*)p, "\\x%02x", encbuf[i]);
                              p += 4;
                            }
                        }
                      n += encidx * 4;
                      encidx = 0;
                    }
                }
            }

        }
      if (!buffer) /* allocate the buffer after the first pass */
        buffer = p = cdk_malloc (n + 1);
      else
        {
          *p = 0; /* make a string */
          return (char*)buffer;
        }
    }
}
