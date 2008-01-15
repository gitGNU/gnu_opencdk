# Makefile.am - Makefile for the regression tests.
#       Copyright (C) 2003, 2007 Timo Schulz
#       Copyright (C) 2006, 2007 Free Software Foundation, Inc.
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

EXTRA_DIST = pub.gpg pub-asc.gpg sec.gpg sec-with-pwd.gpg ts.gpg \
		exp-key.gpg wkold.gpg pub-key.asc newkey.gpg newkey.sec \
		testpa.c \
		plain-test-pubenc.asc plain-test-sym.gpg photo-key.gpg \
		plain-test-cs.asc plain-test-pubenc-part.gpg plain-test.gpg \
		plain-test.sig t-support.h

#SUBDIRS = nio

INCLUDES= -I$(top_srcdir)/src

AM_LDFLAGS = -no-install
AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS)

CLEANFILES = plain-test

LDADD = ../src/libopencdk.la

if HAVE_W32_SYSTEM
# there is a problem with some tests and WINE
TESTS = basic
check_PROGRAMS = basic
else
TESTS = t-stream t-sign t-key t-encr t-keydb t-misc basic
check_PROGRAMS = t-sign t-key t-encr t-stream t-keydb t-misc basic
endif

noinst_HEADER = t-support.h
noinst_PROGRAMS = $(TESTS)
