#!/bin/sh

perl Build.PL
./Build dist
cpan-upload Mail-DMARC-*.tar.gz
./Build distclean