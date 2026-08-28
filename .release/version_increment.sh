#!/bin/sh

set -e

. .release/base.sh

assure_repo_is_clean

NEWVER="$(get_version)"

update_modules()
{
    # shellcheck disable=SC2046
    sed -i '' \
        -e "/VERSION =/ s/= .*$/= '$NEWVER';/" \
        -e "/^version / s/.*/version $NEWVER/" \
        $(find lib -type f -name '*.pm')

    git add lib
}

update_meta()
{
    # Build.PL does not touch META.*; distmeta is what rewrites them, and it
    # needs the Build script that distclean then removes
    perl Build.PL
    ./Build distmeta
    ./Build distclean
    git add META.*
}

update_modules
update_meta

if ! repo_is_clean; then
    git status
    git add .
    git commit -m "release version $NEWVER"
fi
