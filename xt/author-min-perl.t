#!perl

BEGIN {
  unless ($ENV{AUTHOR_TESTING}) {
    require Test::More;
    Test::More::plan(skip_all => 'these tests are for testing by the author');
  }
}

use strict;
use warnings;

use CPAN::Meta;
use Test::More;
use version;

sub slurp {
    my ($file) = @_;
    open my $fh, '<', $file or die "open $file: $!";
    local $/;
    return <$fh>;
}

sub declared_in {
    my ( $file, $key ) = @_;
    my @found = slurp($file) =~ /"\Q$key\E"\s*=>\s*"([^"]+)"/g;
    is( scalar @found, 1, "$file declares $key once" ) or return;
    return $found[0];
}

sub meta_perl {
    my ($file) = @_;
    return CPAN::Meta->load_file($file)->effective_prereqs
        ->requirements_for( 'runtime', 'requires' )
        ->requirements_for_module('perl');
}

# CPAN clients install by META.*, but Build.PL regenerates META.* (see
# .release/version_increment.sh), so a bump in only one file silently reverts.
my %min_perl = (
    'Makefile.PL prereqs'          => declared_in( 'Makefile.PL', 'perl' ),
    'Makefile.PL MIN_PERL_VERSION' => declared_in( 'Makefile.PL', 'MIN_PERL_VERSION' ),
    'Build.PL'                     => declared_in( 'Build.PL',    'perl' ),
    'META.json'                    => meta_perl('META.json'),
    'META.yml'                     => meta_perl('META.yml'),
);

my %normalized = map { $_ => version->parse( $min_perl{$_} )->normal } keys %min_perl;
my %distinct   = map { $_ => 1 } values %normalized;

is( scalar keys %distinct, 1, 'minimum Perl version agrees everywhere' )
    or diag join "\n", map {"  $_: $min_perl{$_}"} sort keys %min_perl;

done_testing();
