#!/bin/sh

. .release/base.sh || exit

repo_is_clean || exit

YEAR=$(date "+%Y")

sed -i '' \
    -e "/copyright/ s/20[[:digit:]][[:digit:]]/$YEAR/" \
    LICENSE $(find lib -type f -name '*.pm')

git commit -m "bump copyright to $YEAR"
