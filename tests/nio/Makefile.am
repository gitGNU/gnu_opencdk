
EXTRA_DIST = t-glue.h test-data test-data.lit test-data-red test-data-fmt

INCLUDES= -I$(top_srcdir)/src -I$(top_srcdir)/nio -I$(top_srcdir)/tests

AM_LDFLAGS = -no-install
AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS)

LDADD = ../../src/libopencdk.la ../../nio/libnio.la

if HAVE_W32_SYSTEM
TESTS =
else
TESTS = t-api
check_PROGRAMS = t-api
endif

noinst_PROGRAMS = $(TESTS)
