#!/bin/sh

get_version()
{
    echo "1.$(date '+%Y%m%d')"
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

    if ! grep -q "$THIS_VERSION" Changes.md; then
        echo "OOPS, Changes.md has no entry for version $THIS_VERSION"
        return 1
    fi

    return 0
}