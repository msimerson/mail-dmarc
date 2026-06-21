#!/bin/sh

set -e

. .release/base.sh

assure_repo_is_clean

pod2markdown lib/Mail/DMARC.pm > README.md

if ! repo_is_clean; then
    git add README.md
    git commit -m "doc(README): updated"
fi
