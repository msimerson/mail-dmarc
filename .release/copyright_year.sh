#!/bin/sh

YEAR=$(date "+%Y")

sed -i '' \
    -e "/copyright/ s/20[[:digit:]][[:digit:]]/$YEAR/" \
    LICENSE $(find lib -type f -name '*.pm')

