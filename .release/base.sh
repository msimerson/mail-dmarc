#!/bin/sh

set -e

get_version()
{
    major=$(sed -n "s/.*VERSION = '\([0-9][0-9]*\)\..*/\1/p" lib/Mail/DMARC.pm | head -1)
    echo "${major}.$(date '+%Y%m%d')"
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
