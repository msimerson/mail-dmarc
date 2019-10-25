#!/bin/sh

NEWVER="1.$(date '+%Y%m%d')"
echo "$NEWVER"

sed -i '' \
    -e "/VERSION =/ s/= .*$/= '$NEWVER';/" \
    -e "/^version / s/.*/version $NEWVER/" \
    $(find lib -type f -name '*.pm')
