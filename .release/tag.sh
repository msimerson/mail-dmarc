#!/bin/sh

set -e

. .release/base.sh

assure_repo_is_clean

TAG_NAME="v$(get_version)"
echo "tag $TAG_NAME"

git tag "$TAG_NAME"
git push --tags

#PREV_TAG_NAME=$(gh release list --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName')
PREV_TAG_NAME=$(gh release view --json tagName --jq .tagName)

gh release create \
  "$TAG_NAME" \
  --title "$TAG_NAME" \
  --target master \
  --draft \
  --generate-notes \
  --notes-start-tag "$PREV_TAG_NAME" \

# GitHub CLI api
# https://cli.github.com/manual/gh_api

#gh api \
#  --method POST \
#  -H "Accept: application/vnd.github+json" \
#  -H "X-GitHub-Api-Version: 2022-11-28" \
#  /repos/msimerson/mail-dmarc/releases \
# -f tag_name="$TAG_NAME" \
# -f target_commitish='master' \
# -f name="$TAG_NAME" \
# -F draft=true \
# -F prerelease=false \
# -F generate_release_notes=true
