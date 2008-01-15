# Makefile.am - Makefile template for the new I/O code
# Copyright (C) 2007 Timo Schulz
# This file is part of opencdk

EXTRA_DIST = README

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS) -I$(top_srcdir)/src

noinst_LTLIBRARIES = libnio.la

libnio_la_SOURCES = read-digest.c reader.c read-file.c write-armor.c \
			write-buffer.c write-buffered.c write-compress.c \
			write-file.c write-cipher.c writer.c new-io.h\
			read-buffer.c
			
libnio_la_LIBADD = $(top_builddir)/src/libopencdk.la
