#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

NEWVER="$(get_version)"

# shellcheck disable=SC2046
sed -i '' \
    -e "/VERSION =/ s/= .*$/= '$NEWVER';/" \
    -e "/^version / s/.*/version $NEWVER/" \
    $(find lib -type f -name '*.pm')

if ! repo_is_clean; then
    git add .
    git commit -m "increment version to $NEWVER"
fi
