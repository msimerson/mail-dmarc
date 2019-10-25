#!/bin/sh

TAGNAME="v1.$(date '+%Y%M%d')"
echo "tag $TAGNAME"

git tag "$TAGNAME"