#!/bin/sh

. .release/base.sh || exit

assure_repo_is_clean || exit

TAGNAME="v$(get_version)"
echo "tag $TAGNAME"

git tag "$TAGNAME"
git push --tags

# create a GitHub release
# https://developer.github.com/v3/repos/releases/#create-a-release

curl -u msimerson -X POST https://api.github.com/repos/msimerson/mail-dmarc/releases -H 'Content-Type: application/json' -d '{
  "tag_name": "$TAGNAME",
  "target_commitish": "master",
  "name": "$TAGNAME",
  "body": "Description of the release",
  "draft": true,
  "prerelease": false
}'
