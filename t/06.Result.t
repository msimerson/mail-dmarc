use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok('Mail::DMARC::PurePerl');
use_ok('Mail::DMARC::Result');

my $pp     = Mail::DMARC::PurePerl->new;
my $result = Mail::DMARC::Result->new;

isa_ok( $result, 'Mail::DMARC::Result' );

my $test_dom = 'tnpi.net';
test_published();
test_no_policy();
test_disposition();
test_dkim();
test_dkim_align();
test_spf();
test_result();
test_reason();
test_dkim_meta();

done_testing();
exit;

sub _test_pass_strict {
    $pp->init();
    $pp->header_from($test_dom);
    $pp->dkim(
        [ { domain => $test_dom, result => 'pass', selector => 'apr2013' } ]
    );
    $pp->spf( { domain => $test_dom, result => 'pass', scope => 'mfrom' } );
    $pp->validate();
    delete $pp->result->{published};
    is_deeply(
        $pp->result,
        {   'result'      => 'pass',
            'disposition' => 'none',
            'dkim'        => 'pass',
            'spf'         => 'pass',
            'spf_align'   => 'strict',
            'dkim_meta'   => {
                'domain'   => 'tnpi.net',
                'identity' => '',
                'selector' => 'apr2013',
            },
            'dkim_align' => 'strict',
        },
        "result, pass, strict, $test_dom"
    ) or diag Data::Dumper::Dumper( $pp->result );
}

sub _test_pass_relaxed {
    $pp->init();
    $pp->header_from("www.$test_dom");
    $pp->dkim(
        [ { domain => $test_dom, result => 'pass', selector => 'apr2013' } ]
    );
    $pp->spf( { domain => $test_dom, result => 'pass' } );
    $pp->validate();
    delete $pp->result->{published};

    my $skip_reason;
    if ( !$pp->result->dkim ) {    # typically a DNS failure,
        $skip_reason = "look like DNS is not working";
    }
SKIP: {
        skip $skip_reason, 1 if $skip_reason;

        is_deeply(
            $pp->result,
            {   'result'      => 'pass',
                'dkim'        => 'pass',
                'spf'         => 'pass',
                'disposition' => 'none',
                'dkim_align'  => 'relaxed',
                'dkim_meta'   => {
                    'domain'   => 'tnpi.net',
                    'identity' => '',
                    'selector' => 'apr2013',
                },
                'spf_align' => 'relaxed',
            },
            "pass, relaxed, $test_dom"
        ) or diag Data::Dumper::Dumper( $pp->result );
    }
}

sub _test_fail_strict {
    my $pol = shift || 'reject';
    $pp->init();
    my $from_dom = "www.$test_dom";
    $pp->header_from($from_dom);
    $pp->dkim(
        [ { domain => $test_dom, result => 'pass', selector => 'apr2013' } ]
    );
    $pp->spf( { domain => $test_dom, result => 'pass' } );

    my $policy = $pp->policy->parse("v=DMARC1; p=$pol; aspf=s; adkim=s");
    $policy->{domain} = $from_dom;
    $pp->result->published($policy);
    $pp->{policy} = $policy;
    $pp->validate($policy);

    ok( !$pp->is_dkim_aligned, "is_dkim_aligned, neg" );
    ok( !$pp->is_spf_aligned,  "is_spf_aligned, neg" );
    ok( !$pp->is_aligned(),    "is_aligned, neg" );
    delete $pp->result->{published};
    is_deeply(
        $pp->result,
        {   'disposition' => $pol,
            'dkim'        => 'fail',
            'spf'         => 'fail',
            'result'      => 'fail',
        },
        "result, fail, strict, $test_dom"
    ) or diag Data::Dumper::Dumper( $pp->result );
}

sub _test_fail_sampled_out {
    my $pol = 'reject';
    $pp->init();
    my $from_dom = "www.$test_dom";
    $pp->header_from($from_dom);
    $pp->dkim(
        [ { domain => $test_dom, result => 'pass', selector => 'apr2013' } ]
    );
    $pp->spf( { domain => $test_dom, result => 'pass' } );

    my $policy
        = $pp->policy->parse("v=DMARC1; p=$pol; aspf=s; adkim=s; pct=0");
    $policy->{domain} = $from_dom;
    $pp->result->published($policy);
    $pp->{policy} = $policy;
    $pp->validate($policy);

    ok( !$pp->is_dkim_aligned, "is_dkim_aligned, neg" );
    ok( !$pp->is_spf_aligned,  "is_spf_aligned, neg" );
    ok( !$pp->is_aligned(),    "is_aligned, neg" );
    delete $pp->result->{published};
    is_deeply(
        $pp->result,
        {   'disposition' => 'quarantine',
            'dkim'        => 'fail',
            'spf'         => 'fail',
            'reason'      => [{ 'type' => 'sampled_out' }],
            'result'      => 'fail',
        },
        "result, fail, strict, sampled out, $test_dom"
    ) or diag Data::Dumper::Dumper( $pp->result );
}

sub _test_fail_nonexist {
    $pp->init();
    $pp->{header_from}
        = 'host.nonexistent-tld';    # the ->header_from method would validate
    $pp->validate();

 # some test machines return 'interesting' results for queries of non-existent
 # domains. That's not worth raising a test error.
    my $skip_reason;
    if ( ! $pp->result->reason || $pp->result->reason->[0]->comment ne
        'host.nonexistent-tld not in DNS' ) {
        $skip_reason = "DNS returned 'interesting' results for invalid domain";
    };

SKIP: {
        skip $skip_reason, 1 if $skip_reason;

        is_deeply(
            $pp->result,
            {   'result'      => 'fail',
                'disposition' => 'reject',
                'dkim'        => '',
                'spf'         => '',
                'reason'      => [{
                    'comment' => 'host.nonexistent-tld not in DNS',
                    'type'    => 'other',
                }],
            },
            "result, fail, nonexist"
        ) or diag Data::Dumper::Dumper( $pp->result );
    }
}

sub test_published {
    _test_pass_strict();
    _test_pass_relaxed();
    _test_fail_strict('reject');
    _test_fail_strict('none');
    _test_fail_strict('quarantine');
    _test_fail_sampled_out();
    _test_fail_nonexist();
}

sub test_no_policy {

    $pp->init();
    $pp->header_from( 'responsebeacon.com' );
    $pp->validate();

    my $skip_reason;
    if ( !$pp->result->reason ) {    # typically a DNS failure,
        $skip_reason = "look like DNS is not working";
    };

SKIP: {
        skip $skip_reason, 1 if $skip_reason;

        is_deeply(
            $pp->result,
            {   'result'      => 'fail',
                'disposition' => 'none',
                'dkim'        => '',
                'spf'         => '',
                'reason'      => [{
                    'comment' => 'no policy',
                    'type'    => 'other',
                }],
            },
            "result, fail, nonexist"
        ) or diag Data::Dumper::Dumper( $pp->result );
    };
}

sub test_disposition {

    # positive tests
    foreach (qw/ none reject quarantine NONE REJECT QUARANTINE /) {
        ok( $result->disposition($_), "disposition, $_" );
    }

    # negative tests
    foreach (qw/ non rejec quarantin NON REJEC QUARANTIN /) {
        eval { $result->disposition($_) };
        chomp $@;
        ok( $@, "disposition, neg, $_, $@" );
    }
}

sub test_dkim {
    test_pass_fail('dkim');
}

sub test_dkim_align {
    strict_relaxed('dkim_align');
}

sub test_dkim_meta {
    ok( $result->dkim_meta( { domain => 'test' } ), "dkim_meta" );
}

sub test_spf {
    test_pass_fail('spf');
}

sub test_spf_align {
    strict_relaxed('spf_align');
}

sub test_reason {

    # positive tests
    foreach (
        qw/ forwarded sampled_out trusted_forwarder mailing_list local_policy other /
        )
    {
        ok( $result->reason( type => $_, comment => "test comment" ), "reason type: $_" );
    }

    # negative tests
    foreach (qw/ any reason not in above list /) {
        eval { $result->reason( type => $_ ) };
        chomp $@;
        ok( $@, "reason, $_, $@" );
    }
}

sub test_result {
    test_pass_fail('result');
}

sub test_pass_fail {
    my $sub = shift;

    # positive tests
    foreach (qw/ pass fail PASS FAIL /) {
        ok( $result->$sub($_), "$sub, $_" );
    }

    # negative tests
    foreach (qw/ pas fai PAS FAI /) {
        eval { $result->$sub($_) };
        chomp $@;
        ok( $@, "$sub, neg, $_, $@" );
    }
}

sub strict_relaxed {
    my $sub = shift;

    # positive tests
    foreach (qw/ strict relaxed STRICT RELAXED /) {
        ok( $result->$sub($_), "$sub, $_" );
    }

    # negative tests
    foreach (qw/ stric relaxe STRIC RELAXE /) {
        eval { $result->$sub($_) };
        chomp $@;
        ok( $@, "$sub, neg, $_, $@" );
    }
}

