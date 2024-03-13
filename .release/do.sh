#!/bin/sh

# shellcheck source=.release/base.sh
. .release/base.sh

assure_changes_has_entry || exit

.release/version_increment.sh
.release/copyright_year.sh
.release/update-psl.sh
.release/tag.sh
.release/publish-to-cpan.sh
