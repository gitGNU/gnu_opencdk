#!/bin/sh

# script to check the generated output with the pgpdump parser

PGPDUMP=`which pgpdump`

# check if pgpdump is available, otherwise halt
if test "$?" = "1"; then
 exit 0
fi

FILES="test-filter-out-1 test-filter-out-2 test-filter-out-3 test-chain-out"
FILES="$FILES test-filter-out test-data-red.gpg test-cipher-out test-l-cipher-out"

for f in $FILES; do
 $PGPDUMP "/tmp/cdk_$f" &> /dev/null
 if test "$?" = "0"; then
  echo "$f: ok"
 else
  echo "$f: failed; stop"
  exit 1
 fi
done
exit 0
