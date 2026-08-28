#!/bin/sh

set -e

get_version()
{
    # A release branch pins the version. Without this, a run started before
    # midnight and re-run after it would target a different version, and every
    # step would redo itself against the new date.
    branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')
    case "$branch" in
        release-[0-9]*)
            echo "${branch#release-}"
            return 0
            ;;
    esac

    major=$(sed -n "s/.*VERSION = '\([0-9][0-9]*\)\..*/\1/p" lib/Mail/DMARC.pm | head -1)
    echo "${major}.$(date '+%Y%m%d')"
}

# the commit a tag resolves to, empty if there is no such tag. Annotated tags
# need the ^{commit} peel; without it this returns the tag object instead.
tag_commit()
{
    git rev-parse --quiet --verify "refs/tags/$1^{commit}" 2>/dev/null
}

release_exists()
{
    gh release view "$1" >/dev/null 2>&1
}

repo_is_clean()
{
    if [ -z "$(git status --porcelain)" ]; then
        return 0
    fi

    return 1
}

assure_repo_is_clean()
{
    if repo_is_clean; then return 0; fi

    echo
    echo "ERROR: Uncommitted changes, cowardly refusing to continue..."
    echo
    sleep 2

    git status

    return 1
}

assure_changes_has_entry()
{
    THIS_VERSION=$(get_version)

    if ! grep -q "$THIS_VERSION" CHANGELOG.md; then
        echo "OOPS, CHANGELOG.md has no entry for version $THIS_VERSION"
        return 1
    fi

    return 0
}
