#!/bin/sh

. .release/base.sh || exit

repo_is_clean || exit

TAGNAME="v$(get_version)"
echo "tag $TAGNAME"

git tag "$TAGNAME"
git push --tags