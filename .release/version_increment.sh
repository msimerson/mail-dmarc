#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

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

update_readme()
{
    pod2markdown lib/Mail/DMARC.pm README.md
    git add README.md
}

update_meta()
{
    # update the version in META.* files
    perl Build.PL
    ./Build distclean
    git add META.*
}

update_modules
update_readme
update_meta

if ! repo_is_clean; then
    git status
    git add .
fi

git commit -m "release version $NEWVER"
