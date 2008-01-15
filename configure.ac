dnl configure.ac - OpenCDK Configure script
dnl        Copyright (C) 2002, 2003, 2007 Timo Schulz
dnl        Copyright (C) 2006, 2007  Free Software Foundation, Inc.
dnl
dnl This file is part of OpenCDK.
dnl
dnl OpenCDK is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl OpenCDK is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with OpenCDK; if not, write to the Free Software Foundation,
dnl Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
dnl

AC_PREREQ(2.61)
AC_INIT(opencdk, 0.6.7-cvs, twoaday@gmx.net)
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.9 gnits])
AM_CONFIG_HEADER(config.h)
AB_INIT


# Version numbers (Remember to change them just before a release)
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
AC_SUBST(LT_CURRENT, 10)
AC_SUBST(LT_AGE, 0)
AC_SUBST(LT_REVISION, 6)

# Compute numeric versions
AC_SUBST(MAJOR_VERSION, `echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`)
AC_SUBST(MINOR_VERSION, `echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`)
AC_SUBST(PATCH_VERSION, `echo $PACKAGE_VERSION | sed 's/.*\..*\.\(.*\)/\1/g'`)


AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL

AC_STDC_HEADERS
AC_C_INLINE

AC_CHECK_HEADERS(netdb.h)


if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
     if test "$have_w32_system" = yes; then
     	CFLAGS="$CFLAGS -mms-bitfields"
     fi		
fi


# For some systems we know that we have ld_version scripts.
# Use it then as default.
have_ld_version_script=no
have_w32_system=no
case "${host}" in
    *-mingw32*)
    have_w32_system=yes
    ;;
    *-*-linux*)
    have_ld_version_script=yes
    ;;
    *-*-gnu*)
    have_ld_version_script=yes
    ;;
esac
AC_ARG_ENABLE([ld-version-script],
              AC_HELP_STRING([--enable-ld-version-script],
          [enable/disable use of linker version script.
                              (default is system dependent)]),
	              [have_ld_version_script=$enableval],
           [: ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)

dnl We need to include the winsock library for the mingw32 build
if test "$have_w32_system" = yes; then
 LIBS="$LIBS -lws2_32"
fi

AC_CHECK_HEADER(zlib.h, 
	        AC_CHECK_LIB(z, deflateInit2_,
			     [ac_cv_libz=yes
			      LIBS="$LIBS -lz"
			      AC_DEFINE(HAVE_LIBZ, 1, 
			      [Defined if libz is available])
			     ]))
			     
if test "$ac_cv_libz" != yes; then
    AC_MSG_WARN(
    *** ZLIB was not found. 
    *** You will not be able to compress any data or
    *** to parse any data that has been compressed.
    *** Most OpenPGP programs use compression and as a result
    *** any output by this programs cannot be handled.)
fi

    
AM_PATH_LIBGCRYPT(1:1.2.0,,
            AC_MSG_ERROR([[
	    ***
	    *** libgcrypt was not found. You may want to get it from
	    *** ftp://ftp.gnupg.org/gcrypt/alpha/libgcrypt/
	    ***
	    ]]))
	    
LIBOPENCDK_LIBS="-L${libdir} -lopencdk $LIBGCRYPT_LIBS $LIBS"
LIBOPENCDK_CFLAGS="$LIBGCRYPT_CFLAGS -I${includedir}"
AC_SUBST(LIBOPENCDK_LIBS)
AC_SUBST(LIBOPENCDK_CFLAGS)
    

AC_CONFIG_FILES([Makefile doc/Makefile
		 src/Makefile tests/Makefile
                 src/opencdk.h src/opencdk-config src/opencdk.pc])
AC_OUTPUT
