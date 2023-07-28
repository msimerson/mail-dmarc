#!/bin/sh

DMARC_DEPS="Regexp::Common Config::Tiny File::ShareDir Net::DNS::Resolver DBD::SQLite DBD::Pg DBD::mysql Net::IP Socket6 Email::MIME Net::SMTPS XML::LibXML Email::Sender DBIx::Simple HTTP::Tiny Test::File::ShareDir Test::Output Net::IDN::Encode CGI XML::Validator::Schema Net::DNS::Resolver::Mock"

for _d in $DMARC_DEPS; do
    cpanm --quiet --notest "$_d" || exit
done
