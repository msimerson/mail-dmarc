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
#$dmarc->header_from('example.com');
isa_ok( $dmarc, 'Mail::DMARC::PurePerl' );

test_get_from_dom();
test_get_dom_from_header();
test_fetch_dmarc_record();
test_get_organizational_domain();
test_exists_in_dns();
test_is_spf_aligned();
test_is_dkim_aligned();
test_is_aligned();
test_discover_policy();
test_validate();

# has_valid_reporting_uri
# external_report
# verify_external_reporting

done_testing();
exit;

sub test_discover_policy {
    $dmarc->init();
    $dmarc->header_from('mail-dmarc.tnpi.net');
    my $policy = $dmarc->discover_policy;
    ok( $policy, "discover_policy") or do {
        diag Data::Dumper::Dumper($dmarc->result->evaluated);
        return;
    };
    $policy->apply_defaults;
    is_deeply( $policy, { %test_policy,
            aspf => 'r',          # $pol->new adds the defaults that are
            adkim=> 'r',          #  implied in all DMARC records
            ri   => 86400,
            rf   => 'afrf',
            fo   => 0,
            domain => 'mail-dmarc.tnpi.net',
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

    ok( $dmarc->header_from('example.com'), "spf, set header_from");
    ok( $dmarc->spf( domain => 'example.com', result => 'pass' ), 'spf, set spf');
    ok( $dmarc->is_spf_aligned(), "is_spf_aligned");
    ok( 'strict' eq $dmarc->result->evaluated->spf_align, "is_spf_aligned, strict")
        or diag Dumper($dmarc->result);

    $dmarc->header_from('mail.example.com');
    ok( $dmarc->spf( domain => 'example.com', result => 'pass' ), 'spf, set spf');
    ok( $dmarc->policy->aspf('r'), "spf alignment->r");
    ok( $dmarc->is_spf_aligned(), "is_spf_aligned, relaxed");
    ok( 'relaxed' eq $dmarc->result->evaluated->spf_align, "is_spf_aligned, relaxed");

    $dmarc->header_from('mail.exUmple.com');
    ok( $dmarc->spf( domain => 'example.com', result => 'pass' ), 'spf, set spf');
    ok( ! $dmarc->is_spf_aligned(), "is_spf_aligned, neg");
};

sub test_is_dkim_aligned {

    ok( $dmarc->header_from('example.com'), "dkim, set header_from");
    ok( $dmarc->dkim( [
                {
                domain      => 'mailing-list.com',
                selector    => 'apr2013',
                result      => 'fail',
                human_result=> 'fail (body has been altered)',
                },
                {
                domain      => 'example.com',
                selector    => 'apr2013',
                result      => 'pass',
                human_result=> 'pass',
                },
            ] ), "dkim, setup");

    ok( $dmarc->is_dkim_aligned(), "is_dkim_aligned, strict");

    ok( $dmarc->header_from('mail.example.com'), "dkim, set header_from");
    ok( $dmarc->is_dkim_aligned(), "is_dkim_aligned, relaxed");

# negative test
    ok( $dmarc->header_from('mail.exaNple.com'), "dkim, set header_from");
    ok( $dmarc->is_dkim_aligned(), "is_dkim_aligned, miss");
};

sub test_is_aligned {
    $dmarc->result->evaluated->spf('pass');
    $dmarc->result->evaluated->dkim('pass');
    ok( $dmarc->is_aligned(), "is_aligned, both");

    $dmarc->result->evaluated->dkim('fail');
    ok( $dmarc->is_aligned(), "is_aligned, spf");

    $dmarc->result->evaluated->dkim('pass');
    $dmarc->result->evaluated->spf('fail');
    ok( $dmarc->is_aligned(), "is_aligned, dkim");

    $dmarc->result->evaluated->dkim('fail');
    ok( ! $dmarc->is_aligned(), "is_aligned, none")
        or diag Data::Dumper::Dumper($dmarc->is_aligned());
};

sub test_validate {
# TODO: test various failure modes and results

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

sub test_fetch_dmarc_record {
    my $matches = $dmarc->fetch_dmarc_record('mail-dmark.tnpi.net');
    is_deeply( $matches, [], 'fetch_dmarc_record, non-exist' );
#warn Dumper($matches);

    $matches = $dmarc->fetch_dmarc_record('mail-dmarc.tnpi.net');
    is_deeply( $matches, [ $test_rec ], 'fetch_dmarc_record' );
#warn Dumper($matches);
};

sub test_get_from_dom {
    $dmarc->header_from();
    my %froms = get_test_headers();
    foreach my $h ( keys %froms ) {
        $dmarc->header_from_raw($h);
        my $s = $dmarc->get_dom_from_header();
        ok( $s eq $froms{$h}, "get_from_dom, $s eq $froms{$h}");
    };
};

sub test_get_dom_from_header {
    my %froms = get_test_headers();
    foreach my $h ( keys %froms ) {
        $dmarc->header_from_raw($h);
        my $s = $dmarc->get_dom_from_header();
        ok( $s eq $froms{$h}, "get_dom_from_header, $h");
    };
};

