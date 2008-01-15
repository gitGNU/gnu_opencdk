#!/bin/sh
# gen-doc.sh
#        Copyright (C) 2002, 2007 Timo Schulz
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

rm -f opencdk-api.html
echo "<html>" >> opencdk-api.html
echo "<title>OpenCDK API Overview</title><body>" >> opencdk-api.html
echo "<head></head>" >> opencdk-api.html
cat intro.html >> opencdk-api.html
cd ..
cd src
for i in `ls *.c`; do
    echo -n "creating documentation for...$i "
    ../doc/gdoc -html $i >> ../doc/opencdk-api.html
    echo "ok"
done
echo "</body></html>" >> opencdk-api.html
