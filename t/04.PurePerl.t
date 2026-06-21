use strict;
use warnings;
use feature 'try';
no warnings 'experimental::try';  ## no critic (ProhibitNoWarnings)

use Data::Dumper;
use Net::DNS::Resolver::Mock;
use Test::More;
use Test::Exception;
use URI;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';
use_ok('Mail::DMARC::PurePerl');

my $resolver = new Net::DNS::Resolver::Mock();
$resolver->zonefile_parse(join("\n",
'_dmarc.mail-dmarc.tnpi.net.                        600 TXT "v=DMARC1; p=reject; rua=mailto:invalid@theartfarm.com; ruf=mailto:invalid@theartfarm.com; pct=90"',
'_dmarc.tnpi.net.                                   600 TXT "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@theartfarm.com; ruf=mailto:dmarc-feedback@theartfarm.com; pct=100"    ',
'tnpi.net.                                          600 MX  10 mail.theartfarm.com.',
'tnpi.net._report._dmarc.theartfarm.com.            600 TXT "v=DMARC1"',
'cadillac.net._report._dmarc.theartfarm.com.        600 TXT "v=DMARC1"',
'mail-dmarc.tnpi.net._report._dmarc.theartfarm.com. 600 TXT "v=DMARC1; rua=mailto:invalid-test@theartfarm.com;"',

'invalid-sp-and-with-rua.example.com.               600 MX  10 mail.example.com.',
'invalid-sp-and-without-rua.example.com.            600 MX  10 mail.example.com.',
'_dmarc.invalid-sp-and-with-rua.example.com.        600 TXT "v=DMARC1; p=reject; sp=invalid; rua=mailto:rua@example.com"',
'_dmarc.invalid-sp-and-without-rua.example.com.     600 TXT "v=DMARC1; p=reject; sp=invalid"',
# example.com acts as the org-domain anchor for all *.example.com tests
'example.com.                                       600 MX  10 mail.example.com.',
'_dmarc.example.com.                                600 TXT "v=DMARC1; p=none; psd=n; rua=mailto:dmarc@example.com"',

# DMARCbis tree walk test fixtures
# anchor.dmarctest.net: psd=n → lucky anchor (org domain = anchor.dmarctest.net)
'anchor.dmarctest.net.                          600 MX  10 mail.anchor.dmarctest.net.',
'_dmarc.anchor.dmarctest.net.                   600 TXT "v=DMARC1; p=none; psd=n; rua=mailto:dmarc@anchor.dmarctest.net"',
'sub.anchor.dmarctest.net.                      600 MX  10 mail.anchor.dmarctest.net.',

# psd.dmarctest.net: psd=y → PSD; org domain is one label below (sub.psd.dmarctest.net)
'_dmarc.psd.dmarctest.net.                      600 TXT "v=DMARC1; psd=y"',
'sub.psd.dmarctest.net.                         600 MX  10 mail.sub.psd.dmarctest.net.',
# deep author under the same PSD: org domain is the child of the PSD, not the author
'deep.sub.psd.dmarctest.net.                    600 MX  10 mail.sub.psd.dmarctest.net.',

# t=y testing mode: reject policy should be downgraded to quarantine
'_dmarc.ttest.dmarctest.net.                    600 TXT "v=DMARC1; p=reject; t=y; rua=mailto:dmarc@ttest.dmarctest.net"',
'ttest.dmarctest.net.                           600 MX  10 mail.ttest.dmarctest.net.',

# np tag: sub exists but ghost.np.dmarctest.net is NXDOMAIN
'_dmarc.np.dmarctest.net.                       600 TXT "v=DMARC1; p=none; np=reject; rua=mailto:dmarc@np.dmarctest.net"',
'np.dmarctest.net.                              600 MX  10 mail.np.dmarctest.net.',
'real.np.dmarctest.net.                         600 MX  10 mail.np.dmarctest.net.',
'txtonly.np.dmarctest.net.                      600 TXT "v=SPF1 -all"',

# np absent, sp=quarantine: ghost subdomain falls back to sp (no np tag)
'_dmarc.npnosp.dmarctest.net.                   600 TXT "v=DMARC1; p=none; sp=quarantine; rua=mailto:dmarc@npnosp.dmarctest.net"',
'npnosp.dmarctest.net.                          600 MX  10 mail.npnosp.dmarctest.net.',

# np=none: ghost subdomain, np=none, no enforcement despite p=reject
'_dmarc.npnone.dmarctest.net.                   600 TXT "v=DMARC1; p=reject; np=none; rua=mailto:dmarc@npnone.dmarctest.net"',
'npnone.dmarctest.net.                          600 MX  10 mail.npnone.dmarctest.net.',

# np=reject + t=y: ghost subdomain, reject downgraded to quarantine
'_dmarc.npttest2.dmarctest.net.                 600 TXT "v=DMARC1; p=none; np=reject; t=y; rua=mailto:dmarc@npttest2.dmarctest.net"',
'npttest2.dmarctest.net.                        600 MX  10 mail.npttest2.dmarctest.net.',
''));

my @test_policy = (
    'v', 'DMARC1',    # Section 6.2, Formal Definition
    'p', 'reject',    # the v(ersion) and request(p) are ordered
    'rua', 'mailto:invalid@theartfarm.com',
    'ruf', 'mailto:invalid@theartfarm.com',
    'pct', 90,
);
my %test_policy = @test_policy;

my $n;
my $test_rec = join( '; ',
    map  { $_ . '=' . $test_policy{$_} }
    grep { !( $n++ % 2 ) } @test_policy );  # extract keys

my $dmarc = Mail::DMARC::PurePerl->new;
$dmarc->config('t/mail-dmarc.ini');
 $dmarc->set_resolver($resolver);

isa_ok( $dmarc, 'Mail::DMARC::PurePerl' );

test_get_from_dom();
test_fetch_dmarc_record();
test_get_organizational_domain();
test_tree_walk();
test_exists_in_dns();
test_is_spf_aligned();
test_is_dkim_aligned();
test_is_aligned();
test_is_whitelisted();
test_discover_policy();
test_validate();
test_validate_t_tag();
test_validate_invalid_sp();
test_validate_psd_y();
test_validate_np_tag();
test_has_valid_reporting_uri();
test_external_report();
test_verify_external_reporting( 'tnpi.net',            'theartfarm.com', 1 );
test_verify_external_reporting( 'cadillac.net',        'theartfarm.com', 1 );
test_verify_external_reporting( 'mail-dmarc.tnpi.net', 'theartfarm.com', 1 );
_test_reason();

done_testing();
exit;

sub _test_reason {
    $dmarc->init();
    $dmarc->source_ip('66.128.51.165');
    $dmarc->envelope_to('recipient.example.com');
    $dmarc->envelope_from('dmarc-nonexist.tnpi.net');
    $dmarc->header_from('mail-dmarc.tnpi.net');
    $dmarc->dkim([
            {
            domain      => 'tnpi.net',
            selector    => 'jan2015',
            result      => 'fail',
            human_result=> 'fail (body has been altered)',
        }
    ]);
    $dmarc->spf([
            {   domain => 'tnpi.net',
                scope  => 'mfrom',
                result => 'pass',
            },
            {
                scope  => 'helo',
                domain => 'mail.tnpi.net',
                result => 'fail',
            },
        ]);

    my $policy = $dmarc->discover_policy;
    ok( $policy, "discover_policy" );
    my $result = $dmarc->validate($policy);
    ok( ref $result, "result is a ref");
    ok( $result->{result} eq 'pass', "result=pass");
    ok( $result->{spf} eq 'pass', "spf=pass");
    ok( $result->{disposition} eq 'none', "disposition=none");

    $result->disposition('reject');
    ok( $result->{disposition} eq 'reject', "disposition changed to reject");

    ok( $result->reason( type => 'local_policy' ), "added reason" );
    ok( $result->reason( type => 'local_policy', comment => 'testing' ), "added reason 2" );
    #warn Data::Dumper::Dumper($result->reason);

    ok( $dmarc->save_aggregate(), "save aggregate");
}

sub test_verify_external_reporting {
    my ($dmarc_dom, $dest_dom, $outcome) = @_;
    my $ver = 'verify_external_reporting';

    my $policy = $dmarc->policy->parse(
        "v=DMARC1; p=none; rua=mailto:dmarc-feedback\@$dest_dom");
    $policy->{domain} = $dmarc_dom;
    ok( $policy, "new policy" );
    $dmarc->result->published($policy);

    my $uri = URI->new("mailto:test\@$dest_dom");
    cmp_ok( $outcome, 'eq', $dmarc->$ver( { uri => $uri } ), "$ver, $dmarc_dom, $dest_dom" );

    # a DMARC record with a RUA override
    return if $dmarc_dom ne 'mail-dmarc.tnpi.net';
    my $uri_should_be = $dmarc->report->uri->parse(
        URI->new("mailto:invalid-test\@theartfarm.com") );
    my $uri_via_net
        = $dmarc->report->uri->parse( $dmarc->result->published->rua );
    is_deeply( $uri_via_net->[0], $uri_should_be->[0], "$ver, override rua" );
}

sub test_external_report {

    my @test_doms = qw/ example.com silly.com /;
    foreach my $dom (@test_doms) {

        my $policy = $dmarc->policy->parse('v=DMARC1');
        $policy->{domain} = $dom;
        ok( $policy, "new policy" );
        $dmarc->result->published($policy);

        my $uri = URI->new("mailto:test\@$dom");

        # warn "path: " . $uri->path;
        ok( $uri, "new URI" );
        ok( !$dmarc->external_report($uri),
            "external_report, $uri for $dom" );
    }

    foreach my $dom (@test_doms) {
        my $policy = $dmarc->policy->parse('v=DMARC1');
        $policy->{domain} = "$dom.com";
        ok( $policy, "new policy" );
        $dmarc->result->published($policy);

        my $uri = URI->new("mailto:test\@$dom");

        # warn "path: " . $uri->path;
        ok( $uri, "new URI" );
        ok( $dmarc->external_report($uri), "external_report, $uri for $dom.com" );
    }
}

sub test_has_valid_reporting_uri {
    my @valid = (
        'mailto:dmarc@example.com',    # canonical example
        'mailto:dmarc@example.com,http://example.com/dmarc',    # two matches
        'ftp://dmarc.example.com,http://example.com/dmarc',     # http only
    );

    $dmarc->result->published->{domain} = 'example.com';
    foreach my $v (@valid) {
        my $r_ref = $dmarc->has_valid_reporting_uri($v);
        ok( $r_ref, "has_valid_reporting_uri, $v" );
    }

    my $uris;

    $uris = $dmarc->has_valid_reporting_uri(
        'mailto:invalid@no-premission.example.com' );
    ok( 1 == $uris, "has_valid_reporting_uri, single filtered");

    # invalid tests
    my @invalid = (
        'ftp://ftp.example.com',          # invalid schemes
        'gopher://www.example.com/dmarc',
        'scp://secure.example.com',
        'http://www.example.com/dmarc',   # host doesn't match
    );
    $dmarc->result->published->{domain} = 'example.com';
    foreach my $v (@invalid) {
        my $r = $dmarc->has_valid_reporting_uri($v);
        ok( !$r, "has_valid_reporting_uri, neg, $v" )
            or diag Dumper($r);
    }

    my %real = (); # real life tests

    foreach my $dom ( keys %real ) {
        $dmarc->result->published->{domain} = $dom;
        my $r_ref = $dmarc->has_valid_reporting_uri($real{$dom});
        ok( $r_ref, "has_valid_reporting_uri, $dom" );
    };
}

sub test_discover_policy {
    $dmarc->init();
    $dmarc->header_from('mail-dmarc.tnpi.net');
    my $policy = $dmarc->discover_policy;
    ok( $policy, "discover_policy" )
        or return diag Data::Dumper::Dumper($dmarc);
    $policy->apply_defaults;
    # DMARCbis: rf and ri are deprecated; apply_defaults no longer sets them
    my $expected = { %test_policy,
        aspf  => 'r',
        adkim => 'r',
        fo    => 0,
        domain => 'mail-dmarc.tnpi.net',
    };
    is_deeply( $policy, $expected, 'discover_policy, deeply' );
    is( $dmarc->is_subdomain(), 1, "discover_policy, is_subdomain" );

    $dmarc->init();
    $dmarc->header_from('tnpi.net');
    $policy = $dmarc->discover_policy;
    is( $dmarc->is_subdomain(), 0, "fetch_dmarc_record, is_subdomain" );
}

sub get_test_headers {
    return (
        'From: Sample User <user@example.com>'          => 'example.com',
        'From: Sample Middle User <user@example.com>'   => 'example.com',
        'From: "Sample User" <user@example.com>'        => 'example.com',
        'From: "Sample Middle User" <user@example.com>' => 'example.com',
        'Sample User <user@example.com>'                => 'example.com',
        'user@example.com'                              => 'example.com',
        '<user@example.com>'                            => 'example.com',
        ' <user@example.com > '                         => 'example.com',
        # RFC 7489 §5.6.1: multiple From domains require Sender header;
        # without $dmarc->sender set, get_from_dom returns undef (outside scope)
        'Sample User <user@example.com>,Sample2<user@example2.com>' => '',
        'From: "Test 1.1.5"'                            => '',
    );
}

sub test_is_spf_aligned {

    ok( $dmarc->header_from('example.com'), "spf, set header_from" );
    ok( $dmarc->spf(
            domain => 'example.COM',
            scope  => 'mfrom',
            result => 'pass'
        ),
        'spf, set spf'
    );
    ok( $dmarc->is_spf_aligned(),              "is_spf_aligned" );
    ok( 'strict' eq $dmarc->result->spf_align, "is_spf_aligned, strict" )
        or diag Dumper( $dmarc->result );

    $dmarc->header_from('mail.example.com');
    ok( $dmarc->spf(
            domain => 'example.com',
            scope  => 'mfrom',
            result => 'pass'
        ),
        'spf, set spf'
    );
    ok( $dmarc->policy->aspf('r'),              "spf alignment->r" );
    ok( $dmarc->is_spf_aligned(),               "is_spf_aligned, relaxed" );
    ok( 'relaxed' eq $dmarc->result->spf_align, "is_spf_aligned, relaxed" );

    $dmarc->header_from('mail.exUmple.com');
    ok( $dmarc->spf(
            domain => 'example.com',
            scope  => 'mfrom',
            result => 'pass'
        ),
        'spf, set spf'
    );
    ok( !$dmarc->is_spf_aligned(), "is_spf_aligned, neg" );
}

sub test_is_dkim_aligned {

    ok( $dmarc->header_from('example.com'), "dkim, set header_from" );
    ok( $dmarc->dkim(
            [   {   domain       => 'mailing-list.com',
                    selector     => 'apr2013',
                    result       => 'fail',
                    human_result => 'fail (body has been altered)',
                },
                {   domain       => 'example.com',
                    selector     => 'apr2013',
                    result       => 'pass',
                    human_result => 'pass',
                },
            ]
        ),
        "dkim, setup"
    );

    ok( $dmarc->is_dkim_aligned(), "is_dkim_aligned, strict" );

    ok( $dmarc->header_from('mail.example.com'), "dkim, set header_from" );
    ok( $dmarc->is_dkim_aligned(),               "is_dkim_aligned, relaxed" );

    # negative test
    ok( $dmarc->header_from('mail.exaNple.com'), "dkim, set header_from" );
    ok( !$dmarc->is_dkim_aligned(),              "is_dkim_aligned, miss" );

    # no DKIM signatures
    ok( $dmarc->dkim( [] ), "dkim, no signatures" );
    ok( !$dmarc->is_dkim_aligned(), "is_dkim_aligned, empty" );

    # PSL listed domains

    ok( $dmarc->dkim(
            [   {   domain       => 'net',
                    selector     => 'apr2013',
                    result       => 'pass',
                    human_result => 'pass',
                },
            ]
        ),
        "dkim, setup"
    );

    ok( $dmarc->header_from('net'), "dkim, set header_from" );
    ok( $dmarc->is_dkim_aligned(),               "is_dkim_aligned, relaxed" );

    # negative test
    ok( $dmarc->header_from('example.net'), "dkim, set header_from" );
    ok( !$dmarc->is_dkim_aligned(),              "is_dkim_aligned, miss" );

}

sub test_is_aligned {
    $dmarc->result->spf('pass');
    $dmarc->result->dkim('pass');
    ok( $dmarc->is_aligned(), "is_aligned, both" );

    $dmarc->result->dkim('fail');
    ok( $dmarc->is_aligned(), "is_aligned, spf" );

    $dmarc->result->dkim('pass');
    $dmarc->result->spf('fail');
    ok( $dmarc->is_aligned(), "is_aligned, dkim" );

    $dmarc->result->dkim('fail');
    ok( !$dmarc->is_aligned(), "is_aligned, none" )
        or diag Data::Dumper::Dumper( $dmarc->is_aligned() );
}

sub test_is_whitelisted {
    my %good = (
            '127.0.0.1' => 'local_policy',
            '127.0.0.3' => 'trusted_forwarder',
        );
    foreach ( keys %good ) {
        cmp_ok( $dmarc->is_whitelisted($_), 'eq', $good{$_}, "is_whitelisted, $_, $good{$_}");
    };

    my @bad = qw/ 127.0.0.2 10.0.0.0 /;
    foreach ( @bad ) {
        ok( ! $dmarc->is_whitelisted($_), "is_whitelisted, neg, $_");
    };
};

sub sample_dmarc {
    return (
        config_file   => 'mail-dmarc.ini',
        source_ip     => '192.0.1.1',
        envelope_to   => 'example.com',
        envelope_from => 'cars4you.info',
        dkim          => [],
        spf           => [ { domain => 'unrelated.example.com', scope => 'mfrom', result => 'pass' } ],
        @_,
    );
}

sub test_validate {

    $dmarc = Mail::DMARC::PurePerl->new( sample_dmarc(
        header_from => 'tnpi.net',
        dkim        => [
            {   domain       => 'example.com',
                selector     => 'apr2013',
                result       => 'fail',
                human_result => 'fail (body has been altered)',
            }
        ],
        spf => [ { domain => 'tnpi.net', scope => 'mfrom', result => 'pass' } ],
    ) );
    $dmarc->set_resolver($resolver);
    $dmarc->validate();
    #print Dumper($dmarc->result);
    ok($dmarc->is_spf_aligned(), "validate, one-shot, is_spf_aligned, yes" );
    ok(!$dmarc->is_dkim_aligned(), "validate, one-shot, is_dkim_aligned, no" );
}

sub test_tree_walk {
    # Lucky anchor: psd=n stops the walk; that domain is the org domain
    $dmarc->init;
    $dmarc->header_from('anchor.dmarctest.net');
    my ($rec, $org, $at) = $dmarc->tree_walk('anchor.dmarctest.net');
    ok( $rec, "tree_walk, psd=n anchor: record found" );
    is( $org, 'anchor.dmarctest.net', "tree_walk, psd=n: org = anchor domain" );
    is( $at,  'anchor.dmarctest.net', "tree_walk, psd=n: at = anchor domain" );

    # Subdomain of anchor domain
    $dmarc->init;
    ($rec, $org, $at) = $dmarc->tree_walk('sub.anchor.dmarctest.net');
    ok( $rec, "tree_walk, psd=n anchor: record found for subdomain" );
    is( $org, 'anchor.dmarctest.net', "tree_walk, subdomain walks to anchor" );

    # PSD: psd=y, org domain is one label below
    $dmarc->init;
    ($rec, $org, $at) = $dmarc->tree_walk('sub.psd.dmarctest.net');
    ok( $rec, "tree_walk, psd=y: record found" );
    is( $org, 'sub.psd.dmarctest.net', "tree_walk, psd=y: org = domain below PSD" );

    # PSD with a deeper author: org domain is the PSD's child, not the author
    $dmarc->init;
    ($rec, $org, $at) = $dmarc->tree_walk('deep.sub.psd.dmarctest.net');
    is( $org, 'sub.psd.dmarctest.net',
        "tree_walk, psd=y: deep author resolves org to PSD child" );

    # No DMARC records at all, tree_walk returns undef (get_organizational_domain
    # falls back to PSL for the org domain)
    $dmarc->init;
    ($rec, $org, $at) = $dmarc->tree_walk('bbc.co.uk');
    ok( !$rec, "tree_walk, no records: record is undef" );
    ok( !defined $org, "tree_walk, no records: org is undef (PSL fallback in get_org_dom)" );

    # Caching: second call returns same result without extra DNS queries
    $dmarc->init;
    $dmarc->tree_walk('tnpi.net');
    ok( $dmarc->{_tw_cache}{'tnpi.net'}, "tree_walk, cache populated" );
    ($rec, $org, $at) = $dmarc->tree_walk('tnpi.net');
    is( $org, 'tnpi.net', "tree_walk, cached result correct" );
}

sub test_validate_t_tag {
    # t=y: reject policy should be downgraded to quarantine
    $dmarc->init;
    $dmarc->config('t/mail-dmarc.ini');
    $dmarc->source_ip('192.0.1.1');
    $dmarc->envelope_to('example.com');
    $dmarc->envelope_from('cars4you.info');
    $dmarc->header_from('ttest.dmarctest.net');
    $dmarc->dkim([]);
    $dmarc->spf([{
        domain => 'unrelated.example.com',
        scope  => 'mfrom',
        result => 'pass',
    }]);
    lives_ok { $dmarc->validate() } "validate t=y, validate() did not die";
    my $result = $dmarc->result;
    ok( $result, "validate t=y, result exists" );
    is( $result->disposition, 'quarantine',
        "validate t=y, disposition downgraded from reject to quarantine" );
}

sub test_validate_invalid_sp {
    my %subtests = (
        'invalid-sp-and-with-rua.example.com'    => 'pass',
        'invalid-sp-and-without-rua.example.com' => 'none',
    );
    while (my ($header_from, $expected_result) = each %subtests) {
        $dmarc = Mail::DMARC::PurePerl->new( sample_dmarc(
            header_from => $header_from,
            spf         => [ { domain => $header_from, scope => 'mfrom', result => 'pass' } ],
        ) );
        $dmarc->set_resolver($resolver);
        $dmarc->validate();
        is($dmarc->result->result, $expected_result, "DMARC result is ${expected_result}") or diag Dumper($dmarc->result);
    }
}

sub test_validate_psd_y {
    # psd=y record with no p= tag: $effective_p must default to 'none', no warnings
    $dmarc = Mail::DMARC::PurePerl->new( sample_dmarc(
        header_from => 'sub.psd.dmarctest.net',
    ) );
    $dmarc->set_resolver($resolver);
    my @warns;
    local $SIG{__WARN__} = sub { push @warns, @_ };
    $dmarc->validate();
    my $result = $dmarc->result;
    is( $result->result,      'fail', 'psd=y: result is fail (alignment failed)' );
    is( $result->disposition, 'none', 'psd=y: disposition is none (no p= → default none)' );
    is( $result->published->p, 'none',
        'psd=y: published policy has p=none after discover_policy' );
    ok( !@warns, 'psd=y: no uninitialized-value warnings' )
        or diag "warnings: @warns";
}

sub _run_np_subtests {
    my @subtests = @_;
    for my $t (@subtests) {
        my ($header_from, $expected_disp, $label) = @$t;
        $dmarc = Mail::DMARC::PurePerl->new( sample_dmarc( header_from => $header_from ) );
        $dmarc->set_resolver($resolver);
        $dmarc->validate();
        is( $dmarc->result->disposition, $expected_disp, $label )
            or diag Dumper($dmarc->result);
    }
}

sub test_validate_np_tag {
    # Tests that use the real _subdomain_exists_in_dns: the mock resolver returns
    # NOERROR/NODATA for names in the zone that lack the queried record type, which
    # is enough to exercise the NODATA-handling fix.
    _run_np_subtests(
        # existing subdomain (has MX in mock): p=none applies
        [ 'real.np.dmarctest.net',    'none', 'np tag: existing subdomain uses p=none' ],
        # TXT-only subdomain: NOERROR/NODATA for A/AAAA/MX/NS → name exists → np= must NOT apply
        [ 'txtonly.np.dmarctest.net', 'none', 'np tag: TXT-only subdomain treated as existing (p=none, not np=reject)' ],
    );

    # Ghost-subdomain tests: Net::DNS::Resolver::Mock returns NOERROR/NODATA for
    # unknown names, whereas real DNS returns NXDOMAIN.
    # Override _subdomain_exists_in_dns to simulate NXDOMAIN so we can test that
    # validate() correctly applies the np= tag when the subdomain is non-existent.
    {
        no warnings 'redefine';
        local *Mail::DMARC::PurePerl::_subdomain_exists_in_dns = sub { 0 };
        _run_np_subtests(
            [ 'ghost.np.dmarctest.net',       'reject',     'np tag: non-existent subdomain uses np=reject' ],
            [ 'ghost.npnosp.dmarctest.net',   'quarantine', 'np absent: NXDOMAIN subdomain uses sp=quarantine' ],
            [ 'ghost.npnone.dmarctest.net',   'none',       'np=none: NXDOMAIN subdomain disposition is none' ],
            [ 'ghost.npttest2.dmarctest.net', 'quarantine', 'np+t=y: NXDOMAIN subdomain reject downgraded by t=y' ],
        );
    }
}

sub test_exists_in_dns {
    my %tests = (
        'tnpi.net'                 => 1,
        'fake.mail-dmarc.tnpi.net' => 1,    # organizational name exists
        'no-such-made-up-name-should-exist.com.uk.nonsense' => 0,
    );

    foreach my $dom ( keys %tests ) {
        $dmarc->init;
        my $r = $dmarc->exists_in_dns($dom);
        ok( $r >= $tests{$dom}, "exists_in_dns, $dom, $r" );
    }
}

sub test_get_organizational_domain {
    # DMARCbis: org domain is determined by DNS Tree Walk, not PSL.
    # Domains with a DMARC record in their tree anchor the org domain.
    # When no DMARC records exist in the DNS tree, get_organizational_domain()
    # falls back to the PSL.
    my %domains = (
        # record at _dmarc.tnpi.net (psd=u default): org = tnpi.net
        'tnpi.net'              => 'tnpi.net',
        'www.tnpi.net'          => 'tnpi.net',
        'mail-dmarc.tnpi.net'   => 'tnpi.net',

        # record at _dmarc.anchor.dmarctest.net with psd=n: lucky anchor
        'anchor.dmarctest.net'     => 'anchor.dmarctest.net',
        'sub.anchor.dmarctest.net' => 'anchor.dmarctest.net',

        # no DMARC records anywhere: org domain = from domain
        'bbc.co.uk'             => 'bbc.co.uk',
    );

    foreach ( keys %domains ) {
        $dmarc->init;
        cmp_ok(
            $domains{$_}, 'eq',
            $dmarc->get_organizational_domain($_),
            "get_organizational_domain, $_"
        );
    }
}

sub test_fetch_dmarc_record {
    my ($matches) = $dmarc->fetch_dmarc_record('mail-dmark.tnpi.net');
    is_deeply( $matches, [], 'fetch_dmarc_record, non-exist' );

    #warn Dumper($matches);

    ($matches) = $dmarc->fetch_dmarc_record('mail-dmarc.tnpi.net');
    is_deeply( $matches, [$test_rec], 'fetch_dmarc_record' );

    ($matches) = $dmarc->fetch_dmarc_record('com');
    is_deeply( $matches, [], 'fetch_dmarc_record, 1.2.4 TLD lookup not allowed' );
}

sub test_get_from_dom {

    my %froms = get_test_headers();
    foreach my $h ( keys %froms ) {
        $dmarc->init;
        $dmarc->header_from_raw($h);
        my $s;
        my $error = '';
        try {
            $s = $dmarc->get_from_dom();
        }
        catch ($e) {
            $error = $e;
        }
        if ( $froms{$h} ) {
            ok( $s eq $froms{$h}, "get_from_dom, $s eq $froms{$h}" );
        }
        else {
            chomp $error;
            ok( 1, "get_from_dom, $h, $error" );
        };
    }
}

