use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::PurePerl' );
use_ok( 'Mail::DMARC::Result' );
use_ok( 'Mail::DMARC::Result::Evaluated' );

my $pp = Mail::DMARC::PurePerl->new;
my $result = Mail::DMARC::Result->new;

isa_ok( $result, 'Mail::DMARC::Result' );

my $test_dom = 'tnpi.net';
test_published();
test_evaluated();
test_no_policy();

done_testing();
exit;

sub _test_pass_strict {
    $pp->init();
    $pp->header_from( $test_dom );
    $pp->dkim([{ domain => $test_dom, result=>'pass', selector=> 'apr2013' }]);
    $pp->spf({ domain => $test_dom, result=>'pass' });
    $pp->validate();
    is_deeply( $pp->result->evaluated, {
        'result' => 'pass',
        'disposition' => 'none',
        'dkim' => 'pass',
        'spf'  => 'pass',
        'spf_align' => 'strict',
        'dkim_meta' => {
            'domain' => 'tnpi.net',
            'identity' => '',
            'selector' => 'apr2013',
        },
        'dkim_align' => 'strict',
        },
        "evaluated, pass, strict, $test_dom")
        or diag Data::Dumper::Dumper($pp->result);
};

sub _test_pass_relaxed {
    $pp->init();
    $pp->header_from( "www.$test_dom" );
    $pp->dkim([{ domain => $test_dom, result=>'pass', selector=> 'apr2013' }]);
    $pp->spf({ domain => $test_dom, result=>'pass' });
    $pp->validate();
    is_deeply( $pp->result->evaluated, {
        'result' => 'pass',
        'dkim' => 'pass',
        'spf' => 'pass',
        'disposition' => 'none',
        'dkim_align' => 'relaxed',
        'dkim_meta' => {
            'domain' => 'tnpi.net',
            'identity' => '',
            'selector' => 'apr2013',
        },
        'spf_align' => 'relaxed',
        },
        "evaluated, pass, relaxed, $test_dom")
        or diag Data::Dumper::Dumper($pp->result);
};

sub _test_fail_strict {
    my $pol = shift || 'reject';
    $pp->init();
    my $from_dom = "www.$test_dom";
    $pp->header_from( $from_dom );
    $pp->dkim([{ domain => $test_dom, result=>'pass', selector=> 'apr2013' }]);
    $pp->spf({ domain => $test_dom, result=>'pass' });

    my $policy = $pp->policy->parse( "v=DMARC1; p=$pol; aspf=s; adkim=s" );
    $policy->{domain} = $from_dom;
    $pp->result->published($policy);
    $pp->{policy} = $policy;
    $pp->validate($policy);

    ok( ! $pp->is_dkim_aligned, "is_dkim_aligned, neg");
    ok( ! $pp->is_spf_aligned, "is_spf_aligned, neg");
    ok( ! $pp->is_aligned(), "is_aligned, neg");
    is_deeply( $pp->result->evaluated, {
        'disposition' => $pol,
        'dkim'   => 'fail',
        'spf'    => 'fail',
        'result' => 'fail',
        },
        "evaluated, fail, strict, $test_dom")
        or diag Data::Dumper::Dumper($pp->result);
};

sub _test_fail_sampled_out {
    my $pol = 'reject';
    $pp->init();
    my $from_dom = "www.$test_dom";
    $pp->header_from( $from_dom );
    $pp->dkim([{ domain => $test_dom, result=>'pass', selector=> 'apr2013' }]);
    $pp->spf({ domain => $test_dom, result=>'pass' });

    my $policy = $pp->policy->parse( "v=DMARC1; p=$pol; aspf=s; adkim=s; pct=0" );
    $policy->{domain} = $from_dom;
    $pp->result->published($policy);
    $pp->{policy} = $policy;
    $pp->validate($policy);

    ok( ! $pp->is_dkim_aligned, "is_dkim_aligned, neg");
    ok( ! $pp->is_spf_aligned, "is_spf_aligned, neg");
    ok( ! $pp->is_aligned(), "is_aligned, neg");
    is_deeply( $pp->result->evaluated, {
        'disposition' => 'none',
        'dkim'   => 'fail',
        'spf'    => 'fail',
        'reason' => { 'type' => 'sampled_out' },
        'result' => 'fail',
        },
        "evaluated, fail, strict, sampled out, $test_dom")
        or diag Data::Dumper::Dumper($pp->result);
};

sub _test_fail_nonexist {
    $pp->init();
    $pp->{header_from} = 'host.nonexistent-tld';  # the ->header_from method would validate
    $pp->validate();

# some test machines return 'interesting' results for queries of non-existent
# domains. That's not worth raising a test error.

SKIP: {
    skip "DNS returned 'interesting' results for invalid domain", 1
        if $pp->result->evaluated->reason->comment ne 'host.nonexistent-tld not in DNS';

    is_deeply( $pp->result->evaluated, {
            'result' => 'fail',
            'disposition' => 'reject',
            'dkim' => '',
            'spf'  => '',
            'reason' => {
                'comment' => 'host.nonexistent-tld not in DNS',
                'type' => 'other',
            },
        },
        "evaluated, fail, nonexist")
        or diag Data::Dumper::Dumper($pp->result);
    };
};

sub test_published {
    _test_pass_strict();
    _test_pass_relaxed();
    _test_fail_strict('reject');
    _test_fail_strict('none');
    _test_fail_strict('quarantine');
    _test_fail_sampled_out();
    _test_fail_nonexist();
};

sub test_evaluated {
    ok( $result->evaluated(), "evaluated");
};

sub test_no_policy {

    $pp->init();
    $pp->{header_from} = 'responsebeacon.com';
    $pp->validate();

    is_deeply( $pp->result->evaluated, {
            'result' => 'fail',
            'disposition' => 'none',
            'dkim' => '',
            'spf'  => '',
            'reason' => {
                'comment' => 'no policy',
                'type' => 'other',
            },
        },
        "evaluated, fail, nonexist")
        or diag Data::Dumper::Dumper($pp->result);
};
