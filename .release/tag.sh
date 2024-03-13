#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

TAGNAME="v$(get_version)"
echo "tag $TAGNAME"

git tag "$TAGNAME"
git push --tags

# GitHub CLI api
# https://cli.github.com/manual/gh_api

gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/msimerson/mail-dmarc/releases \
 -f tag_name="$TAGNAME" \
 -f target_commitish='master' \
 -f name="$TAGNAME" \
 -F draft=true \
 -F prerelease=false \
 -F generate_release_notes=true
