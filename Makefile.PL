use strict;
use warnings FATAL => 'all';

use 5.008;
use ExtUtils::MakeMaker;

use File::ShareDir::Install;
$File::ShareDir::Install::INCLUDE_DOTFILES = 1;
$File::ShareDir::Install::INCLUDE_DOTDIRS = 1;
install_share dist => "share";

my %META = (
  "prereqs" => {
    "configure" => {
      "requires" => {
        "ExtUtils::MakeMaker" => 0,
        "File::ShareDir::Install" => "0.06",
      }
    },
    "build" => {
      "requires" => {
      }
    },
    "test" => {
      "recommends" => {
        "XML::SAX::ParserFactory" => "0",
        "XML::Validator::Schema" => "0"
      },
      "requires" => {
        "Test::Exception" => 0,
        "Test::File::ShareDir" => 0,
        "Test::More" => 0,
        "Test::Output" => 0
      }
    },
    "runtime" => {
      "recommends" => {
        "CGI" => 0,
        "HTTP::Request" => 0,
        "JSON" => 0,
        "LWP::UserAgent" => 0,
        "Mail::DKIM::PrivateKey" => 0,
        "Mail::DKIM::Signer" => 0,
        "Mail::DKIM::TextWrap" => 0,
        "Net::HTTP" => 0,
        "Net::SMTPS" => 0,
        "Net::Server::HTTP" => 0,
      },
      "requires" => {
        "CPAN" => 0,
        "Carp" => 0,
        "Config::Tiny" => 0,
        "DBD::SQLite" => "1.31",
        "DBIx::Simple" => "1.35",
        "Data::Dumper" => 0,
        "Email::MIME" => 0,
        "Email::Simple" => 0,
        "Encode" => 0,
        "English" => 0,
        "File::ShareDir" => 0,
        "Getopt::Long" => 0,
        "HTTP::Tiny" => 0,
        "IO::Compress::Gzip" => 0,
        "IO::Compress::Zip" => 0,
        "IO::File" => 0,
        "IO::Socket::SSL" => 0,
        "IO::Uncompress::Gunzip" => 0,
        "IO::Uncompress::Unzip" => 0,
        "Net::DNS::Resolver" => 0,
        "Net::IDN::Encode" => 0,
        "Net::IP" => 0,
        "Net::SSLeay" => 0,
        "POSIX" => 0,
        "Pod::Usage" => 0,
        "Regexp::Common" => "2013031301",
        "Socket" => 0,
        "Socket6" => "0.23",
        "Sys::Hostname" => 0,
        "Sys::Syslog" => 0,
        "URI" => 0,
        "XML::LibXML" => 0,
      }
    },
    "develop" => {
      "requires" => {
      },
      "suggests" => {
      }
    },
  },
  "resources" => {
    "bugtracker" => {
       "web" => "https://github.com/msimerson/mail-dmarc/issues"
    },
    "homepage" => "https://github.com/msimerson/mail-dmarc/wiki",
    "repository" => {
       "type" => "git",
       "url" => "git://github.com/msimerson/mail-dmarc.git",
       "web" => "https://github.com/msimerson/mail-dmarc"
    },
    "license" => [ 'http://dev.perl.org/licenses/' ],
  },
  "optional_features" => {
    "MySQL" => {
      "description" => "MySQL backend storage",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            'DBD::mysql' => '4.001',
          }
        }
      }
    },
    "Postgres" => {
      "description" => "PostgresQL backend storage",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            'DBD::Pg' => '0'
          }
        }
      }
    },
    "web_service" => {
      "description" => "HTTP web UI to DMARC reports",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            "CGI" => 0,
            "HTTP::Request" => 0,
            "JSON" => 0,
            "Net::HTTP" => 0,
            "Net::Server::HTTP" => 0,
          }
        }
      }
    },
    "smtp_sending" => {
      "description" => "Send DMARC reports via SMTP",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            "Net::SMTPS" => 0,
            "Mail::DKIM::PrivateKey" => 0,
            "Mail::DKIM::Signer" => 0,
            "Mail::DKIM::TextWrap" => 0
          }
        }
      }
    },
    "imap_fetch" => {
      "description" => "Retrieve DMARC reports from an IMAP account",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            "Net::IMAP::Simple" => 0,
          }
        }
      }
    }
  },
);

my %MM_ARGS = (
  "NAME" => "Mail::DMARC",
  "ABSTRACT" => "Perl implementation of DMARC",
  "AUTHOR" => "Matt Simerson <msimerson\@cpan.org>, Davide Migliavacca <shari\@cpan.org>, Marc Bradshaw <marc\@marcbradshaw.net>",
  "DISTNAME" => "Mail-DMARC",
  "EXE_FILES" => [
    "bin/dmarc_update_public_suffix_list",
    "bin/dmarc_send_reports",
    "bin/dmarc_httpd",
    "bin/dmarc_lookup",
    "bin/dmarc_receive",
    "bin/dmarc_http_client",
    "bin/dmarc_view_reports"
  ],
  "META_MERGE" => {
    "meta-spec" => { version => 2 },
    "x_contributors" => [
      "Benny Pedersen <me\@junc.eu>",
      "Jean Paul Galea <jeanpaul\@yubico.com>",
      "Marisa Clardy <marisa\@clardy.eu>",
      "Priyadi Iman Nurcahyo <priyadi\@priyadi.net>",
      "Ricardo Signes <rjbs\@cpan.org>"
    ],
  },
  "MIN_PERL_VERSION" => "5.008",
  "VERSION" => "1.20191025",
  "test" => {
    "TESTS" => "t/*.t"
  },
  "clean" => { "FILES" => [ "dmarc_reports.sqlite", "t/reports-test.sqlite", 'MANIFEST.bak' ] },
);

# some nifty boilerplate from local::lib
my $requires = $MM_ARGS{PREREQ_PM} = { %{$META{prereqs}{runtime}{requires}} };

$MM_ARGS{META_ADD} = { 'meta-spec' => { version => 2 }, %META };

for (qw(configure build test runtime)) {
  my $key = $_ eq 'runtime' ? 'PREREQ_PM' : uc $_.'_REQUIRES';
  my $r = $MM_ARGS{$key} = {
    %{$META{prereqs}{$_}{requires} || {}},
    %{delete $MM_ARGS{$key} || {}},
  };
  defined $r->{$_} or delete $r->{$_} for keys %$r;
}

my $eumm_version  = eval $ExtUtils::MakeMaker::VERSION;

if ( $eumm_version < 6.47_01 ) {
  delete $MM_ARGS{MIN_PERL_VERSION};
}

if ( $eumm_version < 6.51_03 ) {
  delete $MM_ARGS{CONFIGURE_REQUIRES};
}

if ( $eumm_version < 6.63_03 ) {
  $MM_ARGS{BUILD_REQUIRES} = {%{$MM_ARGS{BUILD_REQUIRES}}, %{delete $MM_ARGS{TEST_REQUIRES}}};
}

if ( $eumm_version < 6.55_01 ) {
  $MM_ARGS{PREREQ_PM} = {%{$MM_ARGS{PREREQ_PM}}, %{delete $MM_ARGS{BUILD_REQUIRES}}}
}

my %WriteMakefileArgs = (%MM_ARGS);

WriteMakefile(%WriteMakefileArgs);

{
package
MY;
use File::ShareDir::Install qw(postamble);
}
