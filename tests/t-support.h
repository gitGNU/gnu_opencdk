#include <stdlib.h>
#include <gcrypt.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/* Create a non-guessable random part which only consists of
   file system friendly characters. We need to make sure that
   the names are valid on posix and win32 systems. */
static const char*
rndpart (void)
{
  static const char *letters = "abcdefghijklmnopqrstuvwxyz123456789";
  static char rnd[13];
  int i;
    
  gcry_create_nonce (rnd, 12);
  for (i=0; i <= 12; i++)
    {
      char c = letters[(unsigned char)rnd[i] % 35];
      rnd[i] = c;
    }
  rnd[12]=0;
  return rnd;
}   

#ifndef _WIN32
char*
make_tempname (void)
{
  static char buf[1024];
  const char *tmpdir = getenv ("TMP");
  if (!tmpdir)
    tmpdir = "/tmp";
  
  strcpy (buf, tmpdir);
  strcat (buf, "/");
  strcat (buf, "cdk_");
  strcat (buf, rndpart());
  return buf;
}
#else
char*
make_tempname (void)
{
  static char buf[1024];
  
  GetTempPath (1024, buf);
  strcat (buf, "cdk_");
  strcat (buf, rndpart ());
  return buf;
}
#endif

#ifdef _WIN32
#define SEP "\\"
#else
#define SEP "/"
#endif

char*
make_filename (const char *fname)
{
  static char buf[2048];
  const char *srcdir = getenv ("srcdir");
  
  if (!srcdir)
    srcdir = ".";
  strcpy (buf, srcdir);
  strcat (buf, SEP);
  strcat (buf, fname);
  return buf;
}
