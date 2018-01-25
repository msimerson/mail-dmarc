use strict;
use warnings;

use Data::Dumper;
use Test::More;
use URI;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';
use_ok('Mail::DMARC::PurePerl');

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

isa_ok( $dmarc, 'Mail::DMARC::PurePerl' );

test_get_from_dom();
test_fetch_dmarc_record();
test_get_organizational_domain();
test_exists_in_dns();
test_is_spf_aligned();
test_is_dkim_aligned();
test_is_aligned();
test_is_whitelisted();
test_discover_policy();
test_validate();
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

    #delete $dmarc->{public_suffixes};
    #delete $dmarc->{resolver};
    #delete $dmarc->{config};
    #warn Data::Dumper::Dumper($dmarc);
}

sub test_verify_external_reporting {
    my ( $dmarc_dom, $dest_dom, $outcome ) = @_;
    my $ver = 'verify_external_reporting';

    my $policy;
    eval {
        $policy = $dmarc->policy->parse(
            "v=DMARC1; p=none; rua=mailto:dmarc-feedback\@$dest_dom");
    };
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
        ok( $dmarc->external_report($uri),
            "external_report, $uri for $dom.com"
        );
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

    $dmarc->result->published->{domain} = 'dmarc-qa.com';
    my $uris = $dmarc->has_valid_reporting_uri(
        'mailto:mailto:a@dmarc-qa.com,mailto:b@dmarc-qa.com' );
    ok( 2 == $uris, "has_valid_reporting_uri, 1.5.1 multiple");
#print Dumper(\@uris);

    $uris = $dmarc->has_valid_reporting_uri(
        'mailto:mailto:a@dmarc-qa.com,mailto:b@dmarc-qa.com,mailto:invalid@no-premission.example.com' );
    ok( 2 == $uris, "has_valid_reporting_uri, multiple filtered");

    $uris = $dmarc->has_valid_reporting_uri(
        'mailto:invalid@no-premission.example.com' );
    ok( 0 == $uris, "has_valid_reporting_uri, single filtered");

    # invalid tests
    my @invalid = (
        'ftp://ftp.example.com',          # invalid schemes
        'gopher://www.example.com/dmarc',
        'scp://secure.example.com',
        'http://www.example.com/dmarc',   # host doesn't match
        'a@dmarc-qa.com',                 # 1.4.6 missing scheme
    );
    $dmarc->result->published->{domain} = 'example.com';
    foreach my $v (@invalid) {
        my $r = $dmarc->has_valid_reporting_uri($v);
        ok( !$r, "has_valid_reporting_uri, neg, $v" )
            or diag Dumper($r);
    }

# real life tests
    my %real = (
#           'email.wnd.com' => 'mailto:dmarc-722-08-92xze@emvdmarc.com'
            );

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
    my $expected = {   %test_policy,
        aspf  => 'r',      # $pol->new adds the defaults that are
        adkim => 'r',      #  implied in all DMARC records
        ri    => 86400,
        rf    => 'afrf',
        fo    => 0,
        domain => 'mail-dmarc.tnpi.net',
    };
    is_deeply( $policy, $expected, 'discover_policy, deeply' );

    $policy = $dmarc->discover_policy('multiple.dmarc-qa.com');
#   warn Dumper($policy);
    ok( ! $policy, 'discover_policy, 1.3.3 multiple DMARC records not allowed' );
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
        'Sample User <user@example.com>,Sample2<user@example2.com>' =>
            'example2.com',
        'From: test@dmarc-qa.com'                       => 'dmarc-qa.com',
        'From: <test@dmarc-qa.com>'                     => 'dmarc-qa.com',
        'From: "Test 1.1.3" <test@dmarc-qa.com>'        => 'dmarc-qa.com',
        'From: Test 1.1.4" <test@dmarc-qa.com>'         => 'dmarc-qa.com',
        'From: "test@alt.dmarc-qa.com" <test@dmarc-qa.com>'=>'dmarc-qa.com',
        ''                                              => '',
        'From: "Test 1.1.11" <test1@dmarc-qa.com>, "Test 1.1.11" <test2@alt.dmarc-qa.com>'                                                 => 'alt.dmarc-qa.com',
        'From: "Test 1.1.8"
            <test@dmarc-qa.com>'                        => 'dmarc-qa.com',
        'From: "Test 1.1.7" <nope@test@dmarc-qa.com>'   => '',
        'From: Test 1.1.6 <test@dmarc-qa.com>'          => 'dmarc-qa.com',
        'From: "Test 1.1.5"'                            => '',
    );
}

sub test_is_spf_aligned {

    ok( $dmarc->header_from('example.com'), "spf, set header_from" );
    ok( $dmarc->spf(
            domain => 'example.com',
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

sub test_validate {

    my %sample_dmarc = (
        config_file   => 'mail-dmarc.ini',
        source_ip     => '192.0.1.1',
        envelope_to   => 'example.com',
        envelope_from => 'cars4you.info',
        header_from   => 'tnpi.net',
        dkim          => [
            {   domain       => 'example.com',
                selector     => 'apr2013',
                result       => 'fail',
                human_result => 'fail (body has been altered)',
            }
        ],
        spf => [
            {   domain => 'tnpi.net',
                scope  => 'mfrom',
                result => 'pass',
            }
        ],
    );

    $dmarc = Mail::DMARC::PurePerl->new(%sample_dmarc);
    eval { $dmarc->validate(); };
    #print Dumper($dmarc->result);
    ok($dmarc->is_spf_aligned(), "validate, one-shot, is_spf_aligned, yes" );
    ok(!$dmarc->is_dkim_aligned(), "validate, one-shot, is_dkim_aligned, no" );

    # TODO: mock up a Mail::DKIM::Verifier and replace $sample_dmarc{dkim}
    #$dmarc = Mail::DMARC::PurePerl->new(%sample_dmarc);
    #eval { $dmarc->validate(); };
    #print Dumper($dmarc->result);
    #ok($dmarc->is_spf_aligned(), "validate, one-shot, is_spf_aligned, yes" );
    #ok(!$dmarc->is_dkim_aligned(), "validate, one-shot, is_dkim_aligned, Mail-DKIM, yes" );

    # TODO: mock up a Mail::SPF::Result. Replace $sample_dmarc{spf}. Test again.
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
    my %domains = (
        'tnpi.net'        => 'tnpi.net',
        'www.tnpi.net'    => 'tnpi.net',
        'plus.google.com' => 'google.com',
        'bbc.co.uk'       => 'bbc.co.uk',
        'www.bbc.co.uk'   => 'bbc.co.uk',
    );

    foreach ( keys %domains ) {
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

    ($matches) = $dmarc->fetch_dmarc_record('one_one.test.dmarc-qa.com');
    my $policy = $dmarc->policy->parse( $matches->[0] );
    cmp_ok( $policy->p, 'eq', 'reject', "fetch_dmarc_record, 1.2.1 one_one.test.dmarc-qa.com" );

    ($matches) = $dmarc->fetch_dmarc_record('dmarc-qafail.com');
    cmp_ok( 0, '==', scalar @$matches, "fetch_dmarc_record, 1.2.2 DNS error");

    ($matches) = $dmarc->fetch_dmarc_record('alt.dmarc-qa.com');
    $policy = $dmarc->policy->parse( $matches->[0] );
    cmp_ok( $policy->p, 'eq', 'none', "fetch_dmarc_record, 1.2.3 DNS error subdomain");

    ($matches) = $dmarc->fetch_dmarc_record('servfail.dmarc-qa.com');
    eval { $policy = $dmarc->policy->parse( $matches->[0] ) } if scalar @$matches;
    cmp_ok( $policy->p, 'eq', 'none', "fetch_dmarc_record, 1.2.3 DNS srvfail");

    ($matches) = $dmarc->fetch_dmarc_record('com');
    is_deeply( $matches, [], 'fetch_dmarc_record, 1.2.4 TLD lookup not allowed' );

    ($matches) = $dmarc->fetch_dmarc_record('cn.dmarc-qa.com');
    eval { $policy = $dmarc->policy->parse( $matches->[0] ) } if scalar @$matches;
    cmp_ok( $policy->p, 'eq', 'reject', "fetch_dmarc_record, 1.2.5 CNAME results in Org match");

    ($matches) = $dmarc->fetch_dmarc_record('unrelated.dmarc-qa.com');
    eval { $policy = $dmarc->policy->parse( $matches->[0] ) } if scalar @$matches;
    cmp_ok( $policy->p, 'eq', 'reject', "fetch_dmarc_record, 1.3.1 unrelated TXT");

    ($matches) = $dmarc->fetch_dmarc_record('mixed.dmarc-qa.com');
    eval { $policy = $dmarc->policy->parse( $matches->[0] ) } if scalar @$matches;
    cmp_ok( $policy->p, 'eq', 'none', "fetch_dmarc_record, 1.3.1 mixed TXT");

    #warn Dumper($matches);
}

sub test_get_from_dom {

    my %froms = get_test_headers();
    foreach my $h ( keys %froms ) {
        $dmarc->init;
        $dmarc->header_from_raw($h);
        my $s;
        eval { $s = $dmarc->get_from_dom() };
        if ( $froms{$h} ) {
            ok( $s eq $froms{$h}, "get_from_dom, $s eq $froms{$h}" );
        }
        else {
            chomp $@;
            ok( 1, "get_from_dom, $h, $@" );
        };
    }
}

