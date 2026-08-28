#!/bin/sh

set -e

# shellcheck source=.release/base.sh
. .release/base.sh

assure_repo_is_clean

PSL=share/public_suffix_list

# a half-written .new left by a failed transfer would make the next run see a
# dirty repo and refuse to start
trap 'rm -f "$PSL.new"' EXIT

# straight to $PSL would leave a truncated list committed if the transfer died
curl --fail --silent --show-error \
    --output "$PSL.new" \
    https://publicsuffix.org/list/effective_tld_names.dat
mv "$PSL.new" "$PSL"

if ! repo_is_clean; then
    git add "$PSL"
    git commit -m "chore: updated PSL"
fi
