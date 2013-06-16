
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "Module::Build" => "0.3601"
  },
  "configure_requires" => {
    "ExtUtils::MakeMaker" => "6.30",
    "File::ShareDir::Install" => "0.03",
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "Perl implementation of DMARC",
  "dist_author" => [
    "Matt Simerson <msimerson\@cpan.org>",
    "Davide Migliavacca <shari\@cpan.org>"
  ],
  "dist_name" => "Mail-DMARC",
  "dist_version" => "1.20130616",
  "license" => "perl",
  "module_name" => "Mail::DMARC",
  "recommends" => {
    "CGI" => 0,
    "DBD::SQLite" => "1.31",
    "DBIx::Simple" => 0,
    "Email::MIME" => 0,
    "Email::Simple" => 0,
    "IO::Compress::Gzip" => 0,
    "IO::Compress::Zip" => 0,
    "IO::Uncompress::Gunzip" => 0,
    "IO::Uncompress::Unzip" => 0,
    "JSON" => 0,
    "Net::HTTP" => 0,
    "Net::IMAP::Simple" => 0,
    "Net::SMTPS" => 0,
    "XML::LibXML" => 0
  },
  "recursive_test_files" => 1,
  "requires" => {
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
    "IO::Compress::Gzip" => 0,
    "IO::Compress::Zip" => 0,
    "IO::File" => 0,
    "IO::Uncompress::Gunzip" => 0,
    "IO::Uncompress::Unzip" => 0,
    "JSON" => 0,
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
    "parent" => 0,
    "perl" => "5.008",
    "strict" => 0,
    "warnings" => 0
  },
  "script_files" => [
    "bin/dmarc_httpd",
    "bin/dmarc_lookup",
    "bin/dmarc_receive",
    "bin/dmarc_send_reports",
    "bin/dmarc_view_reports",
    "bin/install_deps.pl"
  ],
  "share_dir" => {
    "dist" => "share"
  },
  "test_requires" => {
    "Test::More" => 0
  }
);


unless ( eval { Module::Build->VERSION(0.4004) } ) {
  my $tr = delete $module_build_args{test_requires};
  my $br = $module_build_args{build_requires};
  for my $mod ( keys %$tr ) {
    if ( exists $br->{$mod} ) {
      $br->{$mod} = $tr->{$mod} if $tr->{$mod} > $br->{$mod};
    }
    else {
      $br->{$mod} = $tr->{$mod};
    }
  }
}

my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
