use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::URI';
use_ok($mod);
my $uri = $mod->new;
isa_ok( $uri, $mod );

test_get_size_limit();
test_parse();

done_testing();
exit;

sub test_get_size_limit {
    my %tests = (
        '51m' => 53477376,
        '20k' => 20480,
        '5m'  => 5242880,
        '10m' => 10485760,
        '1g'  => 1073741824,
        '500' => 500,
    );

    foreach my $t ( keys %tests ) {
        cmp_ok( $uri->get_size_limit($t),
            '==', $tests{$t}, "get_size_limit, $tests{$t}" );
    }

    is( $uri->get_size_limit(undef), 0, 'get_size_limit undef means no limit' );

    eval { $uri->get_size_limit('7x') };
    like( $@, qr/unrecognized unit/i, 'get_size_limit croaks on invalid unit' );
}

sub test_parse {
    my @good = (
        'http://www.example.com/dmarc-feedback',
        'https://www.example.com/dmarc-feedback',
        'mailto:dmarc@example.com',
        'mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m',
    );

    foreach (@good) {
        my $uris = $uri->parse($_);
        ok( $uris,         "parse, $_" );
        ok( scalar @$uris, "parse, count " . scalar @$uris );
    }

    my $mixed = $uri->parse(
        'mailto:good@example.com,ftp://invalid.example,https://ok.example/path!20k,MAILTO:bad@example.com'
    );
    is( scalar @$mixed, 2, 'parse filters unsupported or malformed schemes' );

    eval { $uri->parse() };
    like( $@, qr/URI string is required/i, 'parse croaks without URI string' );
}
