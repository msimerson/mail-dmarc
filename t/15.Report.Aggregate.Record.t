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
    my $r;
    my %id;
    eval { $r = $rec->identifiers( \%id ); };
    chomp $@;
    ok( $@, "identifiers, empty, as ref: $@") or diag Dumper($r);

    $id{envelope_to} = 'to.example.com';
    eval { $r = $rec->identifiers( \%id ) };
    chomp $@;
    ok( $@, "identifiers, missing header_from: $@");

    $id{header_from} = 'from.example.com';
#   noisy test, causes a carp emission
#   ok( $r = $rec->identifiers( \%id ), "identifiers, sufficient") or diag Dumper($r);

    $id{envelope_from} = 'from.example.com';
    ok( $rec->identifiers( \%id ), "identifiers, complete") or diag Dumper ($r);
};

sub test_auth_results {
    my $r;
    my %auth;
    eval { $r = $rec->auth_results( \%auth ); };
    chomp $@;
    ok( $@, "auth_results, empty, as ref: $@") or diag Dumper($r);

    $auth{spf} = [ { result => 'none' } ];
#   noisy test, causes a carp
#   ok( $rec->auth_results( \%auth ), "auth_results, sufficient");

    $auth{dkim} = [ { result => 'none' } ];
    ok( $rec->auth_results( \%auth ), "auth_results, complete");

};

sub test_row {
    my $r;
    my %row;
    eval { $r = $rec->row( \%row ); };
    chomp $@;
    ok( $@, "row, empty: $@") or diag Dumper($r);

    $row{source_ip} = $ip;
    eval { $r = $rec->row( \%row ); };
    chomp $@;
    ok( $@, "row, missing count: $@") or diag Dumper($r);

    $row{count} = 1;
    eval { $r = $rec->row( \%row ); };
    chomp $@;
    ok( $@, "row, missing policy_evaluated: $@") or diag Dumper($r);

    $row{policy_evaluated} = { disposition => 'none', spf => 'fail', dkim => 'fail' };
    ok( $r = $rec->row( \%row ), "row, ok") or diag Dumper($r);
};

