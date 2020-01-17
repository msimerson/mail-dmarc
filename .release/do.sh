#!/bin/sh

# shellcheck source=.release/base.sh
. .release/base.sh

assure_changes_has_entry || exit

.release/copyright_year.sh
.release/version_increment.sh
.release/readme.sh
.release/update-psl.sh
.release/tag.sh
.release/publish-to-cpan.sh

git checkout -- META.json META.yml
