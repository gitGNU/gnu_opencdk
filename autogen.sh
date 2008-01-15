#!/bin/sh

# mingw32 build support for the library
# To build the DLL, you need a import lib of libgpg-error and libgcrypt
if test "$1" = "--build-w32"; then
    w32root="$HOME/w32root"
    ./configure --host=i586-mingw32msvc --target=i586-mingw32msvc \
      --with-libgcrypt-prefix=${w32root} --prefix=${w32root}
    exit
fi

aclocal -I m4 -I . && \
libtoolize -c --force --automake && \
autoheader  && \
automake -a -c --gnu || automake -a -c --gnu
autoconf

echo "You can now run \"./configure --enable-maintainer-mode\" and \"make\""
