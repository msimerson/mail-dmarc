
use strict;
use warnings;

use 5.008;

use ExtUtils::MakeMaker 6.30;

use File::ShareDir::Install;
install_share dist => "share";


my %WriteMakefileArgs = (
  "ABSTRACT" => "Perl implementation of DMARC",
  "AUTHOR" => "Matt Simerson <msimerson\@cpan.org>, Davide Migliavacca <shari\@cpan.org>",
  "BUILD_REQUIRES" => {
    "Module::Build" => "0.3601"
  },
  "CONFIGURE_REQUIRES" => {
    "ExtUtils::MakeMaker" => "6.30",
    "File::ShareDir::Install" => "0.03",
    "Module::Build" => "0.3601"
  },
  "DISTNAME" => "Mail-DMARC",
  "EXE_FILES" => [
    "bin/dmarc_http_client",
    "bin/dmarc_httpd",
    "bin/dmarc_lookup",
    "bin/dmarc_receive",
    "bin/dmarc_send_reports",
    "bin/dmarc_view_reports",
    "bin/install_deps.pl"
  ],
  "LICENSE" => "perl",
  "NAME" => "Mail::DMARC",
  "PREREQ_PM" => {
    "CGI" => 0,
    "CPAN" => 0,
    "Carp" => 0,
    "Config::Tiny" => 0,
    "DBIx::Simple" => 0,
    "Data::Dumper" => 0,
    "Email::MIME" => 0,
    "Email::Simple" => 0,
    "Encode" => 0,
    "English" => 0,
    "File::ShareDir" => 0,
    "Getopt::Long" => 0,
    "HTTP::Request" => 0,
    "IO::Compress::Gzip" => 0,
    "IO::Compress::Zip" => 0,
    "IO::File" => 0,
    "IO::Uncompress::Gunzip" => 0,
    "IO::Uncompress::Unzip" => 0,
    "JSON" => 0,
    "LWP::UserAgent" => 0,
    "Net::DNS::Resolver" => 0,
    "Net::HTTP" => 0,
    "Net::IP" => 0,
    "Net::SMTPS" => 0,
    "POSIX" => 0,
    "Pod::Usage" => 0,
    "Regexp::Common" => "2013031301",
    "Socket" => 0,
    "Socket6" => "0.23",
    "Sys::Hostname" => 0,
    "URI" => 0,
    "XML::LibXML" => 0,
    "lib" => 0,
    "parent" => 0,
    "strict" => 0,
    "warnings" => 0
  },
  "TEST_REQUIRES" => {
    "Test::More" => 0
  },
  "VERSION" => "1.20140210",
  "test" => {
    "TESTS" => "t/*.t"
  }
);


my %FallbackPrereqs = (
  "CGI" => 0,
  "CPAN" => 0,
  "Carp" => 0,
  "Config::Tiny" => 0,
  "DBIx::Simple" => 0,
  "Data::Dumper" => 0,
  "Email::MIME" => 0,
  "Email::Simple" => 0,
  "Encode" => 0,
  "English" => 0,
  "File::ShareDir" => 0,
  "Getopt::Long" => 0,
  "HTTP::Request" => 0,
  "IO::Compress::Gzip" => 0,
  "IO::Compress::Zip" => 0,
  "IO::File" => 0,
  "IO::Uncompress::Gunzip" => 0,
  "IO::Uncompress::Unzip" => 0,
  "JSON" => 0,
  "LWP::UserAgent" => 0,
  "Module::Build" => "0.3601",
  "Net::DNS::Resolver" => 0,
  "Net::HTTP" => 0,
  "Net::IP" => 0,
  "Net::SMTPS" => 0,
  "POSIX" => 0,
  "Pod::Usage" => 0,
  "Regexp::Common" => "2013031301",
  "Socket" => 0,
  "Socket6" => "0.23",
  "Sys::Hostname" => 0,
  "Test::More" => 0,
  "URI" => 0,
  "XML::LibXML" => 0,
  "lib" => 0,
  "parent" => 0,
  "strict" => 0,
  "warnings" => 0
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.63_03) } ) {
  delete $WriteMakefileArgs{TEST_REQUIRES};
  delete $WriteMakefileArgs{BUILD_REQUIRES};
  $WriteMakefileArgs{PREREQ_PM} = \%FallbackPrereqs;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);

{
package
MY;
use File::ShareDir::Install qw(postamble);
}


