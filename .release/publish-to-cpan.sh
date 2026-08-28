#!/bin/sh

set -e

# shellcheck source=.release/base.sh
. .release/base.sh

DIST="Mail-DMARC-$(get_version).tar.gz"

if [ -n "$PERL_PUBLISH_SETUP" ]; then
	perl -MCPAN -e 'install Module::Build'
	perl -MCPAN -e 'install Mozilla::CA'
	perl -MCPAN -e 'install CPAN::Uploader'
fi

# an unmatched glob is the literal pattern, which rm then fails on. ./Build dist
# also leaves a staging directory behind, so this cannot be rm without -r.
for _f in Mail-DMARC-*;
do
	[ -e "$_f" ] || continue
	echo "rm $_f"
	rm -rf "$_f"
done

perl Build.PL
./Build dist
./Build distclean

if [ ! -f "$DIST" ]; then
	echo "ERROR: expected $DIST, found: $(echo Mail-DMARC-*)"
	exit 1
fi

cpan-upload "$DIST"
