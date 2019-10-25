#!/bin/sh

. .release/base.sh || exit

if ! repo_is_clean; then exit; fi

NEWVER="1.$(get_version)"

sed -i '' \
    -e "/VERSION =/ s/= .*$/= '$NEWVER';/" \
    -e "/^version / s/.*/version $NEWVER/" \
    $(find lib -type f -name '*.pm')

git commit -m "bump version to $NEWVER"
