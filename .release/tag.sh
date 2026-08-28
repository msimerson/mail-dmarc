#!/bin/sh

set -e

# shellcheck source=.release/base.sh
. .release/base.sh

assure_repo_is_clean

TAG_NAME="v$(get_version)"
# tag.gpgsign makes an unadorned 'git tag' want a message from an editor, which
# a script has no way to answer
TAG_MSG="release $(get_version)"
HEAD_COMMIT=$(git rev-parse HEAD)
TAGGED_COMMIT=$(tag_commit "$TAG_NAME" || true)
FORCE=''

if [ -z "$TAGGED_COMMIT" ]; then
    echo "tag $TAG_NAME"
    git tag -m "$TAG_MSG" "$TAG_NAME"
elif [ "$TAGGED_COMMIT" = "$HEAD_COMMIT" ]; then
    echo "tag $TAG_NAME is already on this commit"
elif release_exists "$TAG_NAME"; then
    echo "ERROR: $TAG_NAME has a release but points at $TAGGED_COMMIT, not HEAD."
    echo "Delete that release and tag, or release a new version."
    exit 1
else
    # earlier steps commit as they go, so a re-run that picks up a new PSL
    # leaves the tag behind HEAD. Nothing refers to it yet, so move it.
    echo "moving $TAG_NAME to $HEAD_COMMIT"
    git tag -f -m "$TAG_MSG" "$TAG_NAME"
    FORCE='--force'
fi

# a single tag, not --tags: this should not push unrelated local tags
# shellcheck disable=SC2086
git push $FORCE origin "refs/tags/$TAG_NAME"

if release_exists "$TAG_NAME"; then
    echo "release $TAG_NAME already exists"
    exit 0
fi

PREV_TAG_NAME=$(gh release list --exclude-drafts --exclude-pre-releases \
    --limit 1 --json tagName --jq '.[0].tagName // empty')

# no --target: the tag is already pushed, so the release takes its commit
set -- "$TAG_NAME" --title "$TAG_NAME" --draft --generate-notes
if [ -n "$PREV_TAG_NAME" ]; then
    set -- "$@" --notes-start-tag "$PREV_TAG_NAME"
fi

gh release create "$@"
