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
test_is_valid();
test_parse();

done_testing();
exit;

sub test_new {
# default policy
    my $pol = Mail::DMARC::Policy->new();
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, { p => 'none', pct=>100, adkim=>'r', aspf=>'r' }, "new" );

# default policy
    $pol = Mail::DMARC::Policy->new( p=>'reject',pct => 90, rua=>'mailto:u@d.co' );
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, { p => 'reject', pct=>90, adkim=>'r', aspf=>'r', rua=>'mailto:u@d.co' }, "new, with args" );
};

sub test_parse {
    $pol = $pol->parse( 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; pct=90', 'parse');
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, { v=>'DMARC1', p => 'reject', pct=>90, adkim=>'r', aspf=>'r', rua=>'mailto:dmarc@example.com', ruf=>'mailto:dmarc@example.com', }, "parse" );
};

sub test_is_valid{
    foreach my $p ( qw/ none reject quarantine / ) {
        ok( $pol->is_valid( $p ), "policy->is_valid, pos, $p" );
    };

    foreach my $p ( qw/ other gibberish non-policy words / ) {
        ok( ! $pol->is_valid( $p ), "policy->is_valid, neg, $p" );
    };
};

