use strict;
use warnings;

use Module::Build 0.3601;

my $module_build_args = {
  "build_requires" => {
    "Module::Build" => "0.3601"
  },
  "configure_requires" => {
    "ExtUtils::MakeMaker" => 0,
    "File::ShareDir::Install" => "0.06",
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "Perl implementation of DMARC",
  "dist_author" => [
    "Matt Simerson <msimerson\@cpan.org>",
    "Davide Migliavacca <shari\@cpan.org>",
    "Marc Bradshaw <marc\@marcbradshaw.net>"
  ],
  "dist_name" => "Mail-DMARC",
  "license" => "perl",
  "module_name" => "Mail::DMARC",
  "release_status" => "stable",
  "add_to_cleanup" => [ "dmarc_reports.sqlite", "t/reports-test.sqlite"],
  "recommends" => {
    "CGI" => 0,
    "Mail::DKIM" => 0,
    # "MIME::Lite" => 0,
    "Net::HTTP" => 0,
    "Net::IMAP::Simple" => 0,
    "Net::Server" => 2,
    "Net::SMTPS" => 0,
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
    "IO::Compress::Gzip" => 0,
    "IO::Compress::Zip" => 0,
    "IO::File" => 0,
    "IO::Socket::SSL" => 0,
    "IO::Uncompress::Gunzip" => 0,
    "IO::Uncompress::Unzip" => 0,
    "LWP::UserAgent" => 0,
    "Mail::DKIM::PrivateKey" => 0,
    "Mail::DKIM::Signer" => 0,
    "Mail::DKIM::TextWrap" => 0,
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
    "Test::File::ShareDir" => 0,
    "URI" => 0,
    "XML::LibXML" => 0,
  },
  "auto_features" => {
    "MySQL" => {
      "description" => "MySQL backend storage",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            'DBI'        => '1.5',
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
            'DBI'        => '1.5',
            'DBD::Pg' => '0'
          }
        }
      }
    },
    "web service" => {
      "description" => "HTTP web UI to DMARC reports",
      "prereqs" => {
        "runtime" => {
          "requires" => {
            "CGI" => 0,
            "HTTP::Request" => 0,
            "HTTP::Tiny" => 0,
            "JSON" => 0,
            "Net::HTTP" => 0,
            "Net::Server::HTTP" => 0,
          }
        }
      }
    }
  },
  "recursive_test_files" => 1,
  "script_files" => [
    "bin/dmarc_update_public_suffix_list",
    "bin/dmarc_send_reports",
    "bin/dmarc_httpd",
    "bin/dmarc_lookup",
    "bin/dmarc_receive",
    "bin/dmarc_http_client",
    "bin/dmarc_view_reports"
  ],
  "share_dir" => {
    "dist" => "share"
  },
  "test_requires" => {
    "Test::Exception" => 0,
    "Test::File::ShareDir" => 0,
    "Test::More" => 0,
    "Test::Output" => 0
  },
  "develop_requires" => {
    "Test::Pod" => "1.41"
  },
  "meta_add" => {
  },
  "meta_merge" => {
    "prereqs" => {
      "test" => {
        "recommends" => {
          "XML::SAX::ParserFactory" => "0",
          "XML::Validator::Schema" => "0"
        },
      },
      "develop" => {
        "requires" => {
          "Test::Pod" => "1.41"
        },
        "suggests" => {
          "Test::Perl::Critic" => "0"
        }
      },
    },
    "resources" => {
      "bugtracker" => "https://github.com/msimerson/mail-dmarc/issues",
      "homepage" => "https://github.com/msimerson/mail-dmarc/wiki",
      "repository" => "https://github.com/msimerson/mail-dmarc",
    },
    "x_contributors" => [
      "Benny Pedersen <me\@junc.eu>",
      "Jean Paul Galea <jeanpaul\@yubico.com>",
      "Marisa Clardy <marisa\@clardy.eu>",
      "Priyadi Iman Nurcahyo <priyadi\@priyadi.net>",
      "Ricardo Signes <rjbs\@cpan.org>"
    ],
  }
};

my $fallback_build_requires = {
  "Module::Build" => "0.3601",
  "Test::Exception" => 0,
  "Test::File::ShareDir" => 0,
  "Test::More" => 0,
  "Test::Output" => 0
};

unless ( eval { Module::Build->VERSION(0.4004) } ) {
  delete $module_build_args->{test_requires};
  $module_build_args->{build_requires} = $fallback_build_requires;
}

my $build = Module::Build->new(%$module_build_args);

# if ( $build->prompt( "Database engine", "sqlite" ) ) {
#     $build->notes( 'DB_ENGINE' => $build->args('db_engine') );
# }

$build->create_build_script;
