#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

curl -o share/public_suffix_list https://publicsuffix.org/list/effective_tld_names.dat

if ! repo_is_clean; then
    git add share/public_suffix_list
    git commit -m "chore: updated PSL"
fi
