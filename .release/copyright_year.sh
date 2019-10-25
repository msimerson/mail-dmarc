#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

YEAR=$(date "+%Y")

sed -i '' \
    -e "/copyright/ s/20[[:digit:]][[:digit:]]/$YEAR/" \
    LICENSE $(find lib -type f -name '*.pm')

git commit -m "bump copyright to $YEAR"
