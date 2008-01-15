/* basic.c - basic regression test
 *    Copyright (C) 2006 Free Software Foundation
 *    Author: Simon Josefsson
 *
 * This file is part of OPENCDK.
 *
 * OPENCDK is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OPENCDK is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OPENCDK; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include "opencdk.h"

int
test_misc_functions (void)
{
  cdk_strlist_t list, n;
  const char *str;
  size_t len;
  
  list = NULL;
  cdk_strlist_add (&list, "alpha");
  cdk_strlist_add (&list, "beta");
  cdk_strlist_add (&list, "gamma");

  len = 0;
  n = list;
  while (n != NULL)
    {
      n = cdk_strlist_next (n, &str);
      len++;
    }
  cdk_strlist_free (list);
  if (len != 3)
    return 1;
  return 0;
}

  
int
main (int argc, char **argv)
{
  printf ("OpenCDK header version %s.\n", OPENCDK_VERSION);
  printf ("OpenCDK library version %s.\n", cdk_check_version (NULL));
  
  if (!cdk_check_version (OPENCDK_VERSION))
    return 1;
  
  if (test_misc_functions ())
    return 1;
  
  return 0;
}
