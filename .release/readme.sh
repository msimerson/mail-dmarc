#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

pod2markdown lib/Mail/DMARC.pm > README.md

if ! repo_is_clean; then
    git add README.md
    git commit -m "README: updated"
fi