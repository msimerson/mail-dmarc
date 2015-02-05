use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Aggregate::Record';
use_ok($mod);
my $rec = $mod->new;
isa_ok( $rec, $mod );

my $ip = '192.2.1.1';

test_identifiers();
test_auth_results();
test_row();

done_testing();
exit;

sub test_identifiers {
    my $id = $rec->identifiers;

    ok( $id->envelope_to( 'to.example.com' ), "envelope_to, set");
    ok( $id->envelope_to eq 'to.example.com', "envelope_to, get");

    ok( $id->header_from( 'from.example.com' ), "header_from, set");
    ok( $id->header_from eq 'from.example.com', "header_from, get");

    ok( $id->envelope_from( 'from.example.com' ), "envelope_from, set");
    ok( $id->envelope_from eq 'from.example.com', "envelope_from, get");

    # one shot
    $id = $rec->identifiers(
        envelope_to  => 'to.example.com',
        header_from  => 'from.example.com',
        envelope_from=> 'from.example.com',
    );
    ok( $id->envelope_to eq 'to.example.com', "envelope_to, get");
    ok( $id->header_from eq 'from.example.com', "header_from, get");
    ok( $id->envelope_from eq 'from.example.com', "envelope_from, get");
};

sub test_auth_results {
    my $ar = $rec->auth_results;

    my $expected = bless { dkim => [], spf => [] }, 'Mail::DMARC::Report::Aggregate::Record::Auth_Results';
    is_deeply( $ar, $expected, "auth_results, empty");

    my $spf1 = { domain => 'first', result => 'none', scope => 'helo' };
    $expected = { dkim => [], spf => [ $spf1 ]};
    $ar->spf( { domain => 'first', result => 'none', scope => 'helo' } );
    is_deeply( $ar, $expected, "auth_results, one SPF");

    my $spf2 = { domain => 'second', scope => 'helo', result => 'temperror' };
    $expected = { dkim => [], spf => [ $spf1, $spf2 ] };
    $ar->spf( { domain => 'second', result => 'temperror', scope => 'helo' } );
    is_deeply( $ar, $expected, "auth_results, two SPF");

    my $dkim1 = { domain => 'first', result => 'none' };
    $expected = { dkim => [ $dkim1 ], spf => [ $spf1, $spf2 ] };
    $ar->dkim( $dkim1 );
    is_deeply( $ar, $expected, "auth_results, two SPF, one DKIM");

    my $dkim2 = { domain => 'second', result => 'none' };
    $expected = { dkim => [ $dkim1, $dkim2 ], spf => [ $spf1, $spf2 ] };
    $ar->dkim( $dkim2 );
    is_deeply( $ar, $expected, "auth_results, two SPF, two DKIM");
};

sub test_row {
    my $ar = $rec->row;

    my $expected = bless {}, 'Mail::DMARC::Report::Aggregate::Record::Row';
    is_deeply( $ar, $expected, "row, empty");

    $ar->source_ip( $ip );
    $expected = { source_ip => $ip };
    is_deeply( $ar, $expected, "row, source_ip");

    $ar->count( 1 );
    $expected = { count => 1, source_ip => $ip };
    is_deeply( $ar, $expected, "row, count");

    my $pe = { disposition => 'none', spf => 'fail', dkim => 'fail' };
    $ar->policy_evaluated( $pe );
    $pe->{reason} = [];
    $expected = { policy_evaluated => $pe, count => 1, source_ip => $ip };
    is_deeply( $ar, $expected, "row, policy_evaluated");
};

