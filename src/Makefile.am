# Makefile.am - Makefile for the Libopencdk library
#       Copyright (C) 2003, 2007 Timo Schulz
#       Copyright (C) 2003, 2004, 2005, 2006, 2007 Free Software Foundation
#
# This file is part of OpenCDK.
#
# OpenCDK is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# OpenCDK is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenCDK; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

include_HEADERS = opencdk.h
lib_LTLIBRARIES = libopencdk.la
bin_SCRIPTS = opencdk-config

EXTRA_DIST = opencdk-config.in opencdk.m4 libopencdk.vers opencdk.def

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS) -I$(top_srcdir)/lib -I$(top_builddir)/lib

libopencdk_la_LDFLAGS = -no-undefined $(export_symbols) \
        -version-info @LT_CURRENT@:@LT_REVISION@:@LT_AGE@
	
if HAVE_LD_VERSION_SCRIPT
libopencdk_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libopencdk.vers
endif

if HAVE_W32_SYSTEM
 export_symbols = -export-symbols $(srcdir)/opencdk.def
else
  export_symbols =
endif
	

libopencdk_la_SOURCES = \
        new-packet.c \
	packet.h \
	hash.c \
	strconv.c \
        read-packet.c proc-packet.c \
        write-packet.c \
	context.h \
	main.c \
        verify.c \
        armor.c \
        sig-check.c \
        sign.c \
        keydb.c \
        opencdk.h \
        main.h \
        keylist.c \
        seskey.c \
        pubkey.c \
        misc.c \
        encrypt.c \
        trustdb.c \
        kbnode.c \
        compress.c \
	literal.c \
        cipher.c  \
	stream.c stream.h stream-socket.c \
	types.h \
	filters.h \
	keyserver.c \
	keygen.c 

libopencdk_la_LIBADD = $(LIBGCRYPT_LIBS)

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opencdk.pc
DISTCLEANFILES = $(pkgconfig_DATA)
