#!/bin/sh

get_version()
{
    echo "1.$(date '+%Y%m%d')"
}

repo_is_clean()
{
    if [ -z "$(git status --porcelain)" ]; then
        echo "working dir is clean"
        return 0
    fi

    echo
    echo "ERROR: Uncommitted changes, cowardly refusing to continue..."
    echo
    sleep 2
    git status
    return 1
}
