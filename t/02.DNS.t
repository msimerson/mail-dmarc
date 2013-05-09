use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::DNS' );

my $n;

my $dns = Mail::DMARC::DNS->new;
isa_ok( $dns, 'Mail::DMARC::DNS' );

my $resolv = $dns->get_resolver();
isa_ok( $resolv, 'Net::DNS::Resolver' );

test_is_public_suffix();
test_has_dns_rr();
test_is_valid_ip();
test_is_valid_domain();

done_testing();
exit;

sub test_is_valid_ip {
# positive tests
    foreach ( qw/ 0.0.0.0 1.1.1.1 255.255.255.255 2607:f060:b008:feed::2 / ) {
        ok( $dns->is_valid_ip($_), "is_valid_ip, $_");
    };

# negative tests
    foreach ( qw/ 256.1.1.1 a 1.1.1.256 / ) {
        ok( ! $dns->is_valid_ip($_), "is_valid_ip, neg, $_");
    };
};

sub test_is_valid_domain {

# positive tests
    foreach ( qw/ example.com bbc.co.uk 3.am / ) {
        ok( $dns->is_valid_domain($_), "is_valid_domain, $_");
    };

# negative tests
    foreach ( qw/ example.m bbc.co.k 3.a / ) {
        ok( ! $dns->is_valid_domain($_), "is_valid_domain, $_");
    };

};

sub test_has_dns_rr {

    my %tests = (
        'NS:tnpi.net'                 => 1,
        'NS:fake.mail-dmarc.tnpi.net' => 0,
        'A:www.tnpi.net'              => 1,
        'MX:tnpi.net'                 => 1,
        'MX:gmail.com'                => 1,
    );

    foreach my $dom ( keys %tests ) {
        my $r = $dns->has_dns_rr( split /:/, $dom  );
# no need to raise test errors for CPAN test systems with unreliable DNS
        next if ! $r && $tests{$dom};
        ok( $r >= $tests{$dom}, "has_dns_rr, $dom" );
    }
};

sub test_is_public_suffix {
    my %tests = (
            'www.tnpi.net' => 0,
            'tnpi.net'     => 0,
            'net'          => 1,
            'com'          => 1,
            'co.uk'        => 1,
            '*.uk'         => 1,
            'google.com'   => 0,
            'a'            => 0,
            'z'            => 0,
            );

    foreach my $dom ( keys %tests ) {
        my $t = $tests{$dom} == 0 ? 'neg' : 'pos';
        cmp_ok( $tests{$dom}, '==', $dns->is_public_suffix( $dom ), "is_public_suffix, $t, $dom" );
    };
};

