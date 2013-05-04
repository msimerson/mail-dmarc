use strict;
use warnings;

use Test::More;

use lib 'lib';

use_ok( 'Mail::DMARC::Policy' );

my $pol = Mail::DMARC::Policy->new();
isa_ok( $pol, 'Mail::DMARC::Policy' );

ok( ! $pol->v, "policy, version, neg" );

ok( $pol->v('DMARC1'), "policy, set");
cmp_ok( $pol->v, 'eq', 'DMARC1', "policy, version, pos" );

test_new();
test_is_valid_p();
test_parse();
test_setter_values();

done_testing();
exit;

sub test_setter_values {
    my %good_vals = (
            p      => [ qw/ none reject quarantine NONE REJEcT Quarantine / ],
            v      => [ qw/ DMARC1 dmarc1 / ],
            sp     => [ qw/ none reject quarantine NoNe REjEcT QuarAntine / ],
            adkim  => [ qw/ r s R S / ],
            aspf   => [ qw/ r s R S / ],
            fo     => [ qw/ 0 1 d s D S / ],
#TODO       rua    =>
#TODO       ruf    =>
            rf     => [ qw/ iodef afrf IODEF AFRF / ],
            ri     => [ 0, 1, 1000, 4294967295 ],
            pct    => [ 0, 10, 50, 99, 100 ],
            );

    foreach my $k ( keys %good_vals ) {
        foreach my $t ( @{$good_vals{$k}} ) {
            ok( defined $pol->$k( $t ), "$k, $t");
        };
    };

    my %bad_vals = (
            p      => [ qw/ nonense silly example / ],
            v      => [ 'DMARC2' ],
            sp     => [ qw/ nones rejection quarrantine / ],
            adkim  => [ qw/ relaxed strict / ],
            aspf   => [ qw/ relaxed strict / ],
            fo     => [ qw/ 00 11 dd ss / ],
#TODO       rua    =>
#TODO       ruf    =>
            rf     => [ qw/ iodef2 rfrf2 rfrf / ],
            ri     => [ -1, 'a', 4294967296 ],
            pct    => [ -1, 'f', 101 ],
            );

    foreach my $k ( keys %bad_vals ) {
        foreach my $t ( @{$bad_vals{$k}} ) {
            eval { $pol->$k( $t ); };
            ok( $@, "neg, $k, $t");
        };
    };
};


sub test_new {
# empty policy
    my $pol = Mail::DMARC::Policy->new();
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, {}, "new, empty policy" );

# default policy
    $pol = Mail::DMARC::Policy->new( v=>'DMARC1', p=>'reject',pct => 90, rua=>'mailto:u@d.co' );
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, { v=>'DMARC1', p => 'reject', pct=>90, rua=>'mailto:u@d.co' }, "new, with args" );

# text record
    $pol = Mail::DMARC::Policy->new( 'v=DMARC1; p=reject; rua=mailto:u@d.co; pct=90' );
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, { v=>'DMARC1', p => 'reject', pct=>90, rua=>'mailto:u@d.co' }, "new, with args" );
};

sub test_parse {

    $pol = $pol->parse( 'v=DMARC1; p=reject; rua=mailto:dmarc@example.co; pct=90');
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, { v=>'DMARC1', p => 'reject', pct=>90, rua=>'mailto:dmarc@example.co', }, 'parse' );

};

sub test_is_valid_p {
    foreach my $p ( qw/ none reject quarantine / ) {
        ok( $pol->is_valid_p ( $p ), "policy->is_valid_p, pos, $p" );
    };

    foreach my $p ( qw/ other gibberish non-policy words / ) {
        ok( ! $pol->is_valid_p ( $p ), "policy->is_valid_p, neg, $p" );
    };
};

