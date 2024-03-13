#!/bin/sh

if [ -n "$PERL_PUBLISH_SETUP" ]; then
	perl -MCPAN -e 'install Module::Build'
	perl -MCPAN -e 'install Mozilla::CA'
	perl -MCPAN -e 'install CPAN::Uploader'
fi

for _f in Mail-DMARC-*;
do
	echo "rm $_f"
	rm $_f
done

perl Build.PL
./Build dist
./Build distclean
cpan-upload Mail-DMARC-*.tar.gz
