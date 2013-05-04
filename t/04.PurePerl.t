use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::PurePerl' );

my @test_policy = (
        'v'   , 'DMARC1',    # Section 6.2, Formal Definition
        'p'   , 'reject',    # the v(ersion) and request(p) are ordered
        'rua' , 'mailto:dmarc@example.com',
        'ruf' , 'mailto:dmarc@example.com',
        'pct' ,  90,
        );
my %test_policy = @test_policy;

my $n;
my $test_rec = join('; ',
        map { $_ .'=' . $test_policy{$_} }
        grep{!($n++ % 2)} @test_policy); # extract keys from the ordered array
#die "$test_rec\n";

my $dmarc = Mail::DMARC::PurePerl->new;
isa_ok( $dmarc, 'Mail::DMARC::PurePerl' );

my $resolv = $dmarc->get_resolver();
isa_ok( $resolv, 'Net::DNS::Resolver' );

test_get_from_dom();
test_get_dom_from_header();
test_fetch_dmarc_record();
test_is_public_suffix();
test_get_organizational_domain();
test_has_dns_rr();
test_exists_in_dns();
test_is_spf_aligned();
test_is_dkim_aligned();
test_is_aligned();
test_discover_policy();

# test_validate();

# has_valid_reporting_uri
# external_report
# verify_external_reporting

done_testing();
exit;

sub test_discover_policy {
    my $policy = $dmarc->discover_policy('mail-dmarc.tnpi.net');
    $policy->apply_defaults;
    is_deeply( $policy, { %test_policy,
            aspf => 'r',          # $pol->new adds the defaults that are
            adkim=> 'r',          #  implied in all DMARC records
            ri   => 86400,
            rf   => 'afrf',
            fo   => 0,
            }, 'discover_policy' );
#print Dumper($policy);
};

sub get_test_headers {
    return (
        'From: Sample User <user@example.com>'          => 'example.com',
        'From: Sample Middle User <user@example.com>'   => 'example.com',
        'From: "Sample User" <user@example.com>'        => 'example.com',
        'From: "Sample Middle User" <user@example.com>' => 'example.com',
        'Sample User <user@example.com>'                => 'example.com',
        'user@example.com'                              => 'example.com',
        '<user@example.com>'                            => 'example.com',
        'Sample User <user@example.com>,Sample2<user@example2.com>' => 'example2.com',
        );
};

sub test_is_spf_aligned {

};

sub test_is_dkim_aligned {

};

sub test_is_aligned {

    my %test_request = (
                from_domain       => 'tnpi.net',
                policy            => $dmarc->policy->new( %test_policy, p=>'none' ),
                spf_pass_domain   => '',
                dkim_pass_domains => [],
                );

    $dmarc->init;   # reset results
    ok( ! $dmarc->is_aligned( %test_request ), "is_aligned, no SPF or DKIM");
    $dmarc->init;

    $test_request{policy} = $dmarc->policy->new( %test_policy,p=>'none' );
    $test_request{spf_pass_domain} = 'tnpi.net';
    ok( $dmarc->is_aligned( %test_request ), "is_aligned, SPF only");
    $dmarc->init;

    $test_request{spf_pass_domain}   = '';
    $test_request{dkim_pass_domains} = ['tnpi.net'];
    ok( $dmarc->is_aligned( %test_request ), "is_aligned, DKIM only");
    $dmarc->init;

    $test_request{spf_pass_domain}   = 'tnpi.net';
    $test_request{dkim_pass_domains} = ['tnpi.net'];
    ok( $dmarc->is_aligned( %test_request ), "is_aligned, both");
    $dmarc->init;

    $test_request{spf_pass_domain}   = '';
    $test_request{dkim_pass_domains} = ['tnpi.net'];
    $test_request{policy}            = $dmarc->policy->new( %test_policy, adkim=>'s' );
    $test_request{from_domain}       = 'www.tnpi.net';
    ok( ! $dmarc->is_aligned( %test_request ), "is_aligned, relaxed DKIM match, strict policy");
    $dmarc->init;

    $test_request{policy}            = $dmarc->policy->new( %test_policy,adkim=>'r' );
    ok( $dmarc->is_aligned( %test_request ), "is_aligned, relaxed DKIM match, relaxed policy");
    $dmarc->init;

    $test_request{spf_pass_domain}   = 'tnpi.net';
    $test_request{dkim_pass_domains} = [];
    $test_request{policy}            = $dmarc->policy->new( %test_policy,aspf=>'s' );
    $test_request{from_domain}       = 'www.tnpi.net';
    ok( ! $dmarc->is_aligned( %test_request ), "is_aligned, relaxed SPF match, strict policy");
    $dmarc->init;

    $test_request{policy}            = $dmarc->policy->new( %test_policy, aspf=>'r' );
    ok( $dmarc->is_aligned( %test_request ), "is_aligned, relaxed SPF match, relaxed policy");
    $dmarc->init;
};

sub test_exists_in_dns {
    my %tests = (
        'tnpi.net'                 => 1,
        'fake.mail-dmarc.tnpi.net' => 1, # organizational name exists
        'no-such-made-up-name-should-exist.com.uk.nonsense' => 0,
    );

    foreach my $dom ( keys %tests ) {
        $dmarc->init;
        my $r = $dmarc->exists_in_dns($dom);
        ok( $r >= $tests{$dom}, "exists_in_dns, $dom, $r" );
    }
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
        my $r = $dmarc->has_dns_rr( split /:/, $dom  );
        ok( $r >= $tests{$dom}, "has_dns_rr, $dom" );
    }
};

sub test_get_organizational_domain {
    my %domains = (
            'tnpi.net'        => 'tnpi.net',
            'www.tnpi.net'    => 'tnpi.net',
            'plus.google.com' => 'google.com',
            'bbc.co.uk'       => 'bbc.co.uk',
            'www.bbc.co.uk'   => 'bbc.co.uk',
            );

    foreach ( keys %domains ) {
        cmp_ok( $domains{$_}, 'eq', $dmarc->get_organizational_domain($_), "get_organizational_domain, $_");
    };
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
        cmp_ok( $tests{$dom}, '==', $dmarc->is_public_suffix( $dom ), "is_public_suffix, $t, $dom" );
    };
};

sub test_fetch_dmarc_record {
    my $matches = $dmarc->fetch_dmarc_record('mail-dmark.tnpi.net');
    is_deeply( $matches, [], 'fetch_dmarc_record, non-exist' );
#warn Dumper($matches);

    $matches = $dmarc->fetch_dmarc_record('mail-dmarc.tnpi.net');
    is_deeply( $matches, [ $test_rec ], 'fetch_dmarc_record' );
#warn Dumper($matches);
};

sub test_get_from_dom {
    my %froms = get_test_headers();
    foreach my $h ( keys %froms ) {
        my $s = $dmarc->get_from_dom( { from_header => $h } );
        ok( $s eq $froms{$h}, "get_from_dom, $h");
    };
};

sub test_get_dom_from_header {
    my %froms = get_test_headers();
    foreach my $h ( keys %froms ) {
        my $s = $dmarc->get_dom_from_header( $h );
        ok( $s eq $froms{$h}, "get_dom_from_header, $h");
    };
};

