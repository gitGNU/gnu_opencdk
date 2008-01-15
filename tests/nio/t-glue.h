/* Contains W32 related glue constructs and code. */
#ifdef _WIN32
#include <stdarg.h>

/* Dummy which is needed because of the fact that
   the mingw32 port uses a DLL and this means problem
   with internal cdk functions. */
static void _cdk_log_debug (const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  vfprintf (stderr, fmt, arg);
  va_end (arg);
}
#endif
