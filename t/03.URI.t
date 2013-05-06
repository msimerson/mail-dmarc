use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::URI' );

my $uri = Mail::DMARC::URI->new;
isa_ok( $uri, 'Mail::DMARC::URI' );

test_get_size_limit();
test_is_valid();

done_testing();
exit;

sub test_get_size_limit {
    my %tests = (
        '51m' => 53477376,   '20k' => 20480,
        '5m'  => 5242880,    '10m' => 10485760,
        '1g'  => 1073741824, '500' => 500,
        );

    foreach my $t ( keys %tests ) {
        cmp_ok( $uri->get_size_limit($t), '==', $tests{$t}, "get_size_limit, $tests{$t}");
    };
};

sub test_is_valid {
    my @good = qw[ 
        http://www.example.com/dmarc-feedback
        https://www.example.com/dmarc-feedback
        mailto:dmarc@example.com
        mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m
        ];

    foreach ( @good ) {
        ok( $uri->is_valid($_), "is_valid, $_" );
    };
};
