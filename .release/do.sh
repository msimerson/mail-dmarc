#!/bin/sh

. .release/base.sh

assure_changes_has_entry || exit

.release/copyright_year.sh
.release/bump_version.sh
.release/readme.sh
.release/tag.sh
.release/publish-to-cpan.sh
