use strict;
use warnings;

use Data::Dumper;
use Test::More;
use Test::Output;

use lib 'lib';

use_ok('Mail::DMARC::Policy');

my $pol = Mail::DMARC::Policy->new();
isa_ok( $pol, 'Mail::DMARC::Policy' );

ok( !$pol->v, "policy, version, neg" );

ok( $pol->v('DMARC1'), "policy, set" );
cmp_ok( $pol->v, 'eq', 'DMARC1', "policy, version, pos" );

my $expected_parse_warning = __expected_parse_warning();
test_new();
test_is_valid_p();
test_is_valid_rf();
stderr_is { test_parse() } $expected_parse_warning, 'STDERR yields parse warnings';
test_setter_values();
test_apply_defaults();
test_is_valid();
test_stringify();
handles_common_record_errors();

done_testing();
exit;

sub __expected_parse_warning {
    return <<'EO_PARSE_WARN'
invalid DMARC record, please post this message to
	https://github.com/msimerson/mail-dmarc/issues/39
	v=DMARC1;p=reject;rua=mailto:dmarc-feedback@theartfarm.com;pct=;ruf=mailto:dmarc-feedback@theartfarm.com
invalid DMARC record, please post this message to
	https://github.com/msimerson/mail-dmarc/issues/39
	domain=tnpi.net;v=DMARC1;p=reject;rua=mailto:dmarc-feedback@theartfarm.com;pct=;ruf=mailto:dmarc-feedback@theartfarm.com
EO_PARSE_WARN
;
}

sub test_apply_defaults {

    # empty policy
    my $pol = Mail::DMARC::Policy->new();
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, {}, "new, empty policy" );

    # default policy
    $pol = Mail::DMARC::Policy->new( v => 'DMARC1', p => 'reject' );
    ok( $pol->apply_defaults(), "apply_defaults" );
    my $expected = {
        v     => 'DMARC1',
        p     => 'reject',
        rf    => 'afrf',
        fo    => 0,
        adkim => 'r',
        aspf  => 'r',
        ri    => 86400
    };
    is_deeply( $pol, $expected, "new, with defaults" );
}

sub test_setter_values {
    my %good_vals = (
        p     => [qw/ none reject quarantine NONE REJEcT Quarantine /],
        v     => [qw/ DMARC1 dmarc1 /],
        sp    => [qw/ none reject quarantine NoNe REjEcT QuarAntine /],
        adkim => [qw/ r s R S /],
        aspf  => [qw/ r s R S /],
        fo    => [qw/ 0 1 d s D S 0:d 0:1:d:s /],
        rua   => [
            qw{ http://example.com/pub/dmarc!30m mailto:dmarc-feed@example.com!10m }
        ],
        ruf => [qw{ https://example.com/dmarc?report!1m }],
        rf  => [qw/ iodef afrf IODEF AFRF /],
        ri  => [ 0, 1, 1000, 4294967295 ],
        pct => [ 0, 10, 50, 99, 100 ],
    );

    foreach my $k ( keys %good_vals ) {
        foreach my $t ( @{ $good_vals{$k} } ) {
            ok( defined $pol->$k($t), "$k, $t" );
        }
    }

    my %bad_vals = (
        p     => [qw/ nonense silly example /],
        v     => ['DMARC2'],
        sp    => [qw/ nones rejection quarrantine /],
        adkim => [qw/ relaxed strict /],
        aspf  => [qw/ relaxed strict /],
        fo    => [qw/ 00 11 dd ss /],
        rua   => [qw{ ftp://example.com/pub torrent://piratebay.net/dmarc }],
        ruf   => [qw{ mail:msimerson@cnap.org }],
        rf    => [qw/ iodef2 rfrf2 rfrf /],
        ri    => [ -1, 'a', 4294967296 ],
        pct   => [ -1, 'f', 101, 1.1, '1.0', '5.f1' ],
    );

    foreach my $k ( keys %bad_vals ) {
        foreach my $t ( @{ $bad_vals{$k} } ) {
            eval { $pol->$k($t); };
            ok( $@, "neg, $k, $t" );
        }
    }
}

sub test_new {

    # empty policy
    my $pol = Mail::DMARC::Policy->new();
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply( $pol, {}, "new, empty policy" );

    # default policy
    $pol = Mail::DMARC::Policy->new(
        v   => 'DMARC1',
        p   => 'reject',
        pct => 90,
        rua => 'mailto:u@d.co'
    );
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply(
        $pol,
        { v => 'DMARC1', p => 'reject', pct => 90, rua => 'mailto:u@d.co' },
        "new, with args"
    );

    # text record
    $pol = Mail::DMARC::Policy->new(
        'v=DMARC1; p=reject; rua=mailto:u@d.co; pct=90');
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    is_deeply(
        $pol,
        { v => 'DMARC1', p => 'reject', pct => 90, rua => 'mailto:u@d.co' },
        "new, with args"
    );
}

sub test_parse {

    $pol = $pol->parse(
        'v=DMARC1; p=reject; rua=mailto:dmarc@example.co; pct=90');
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    my $expected = {
        v   => 'DMARC1',
        p   => 'reject',
        pct => 90,
        rua => 'mailto:dmarc@example.co',
    };
    is_deeply( $pol, $expected, 'parse');

    is_deeply(
        $pol->parse(
            'v=DMARC1;p=reject;rua=mailto:dmarc-feedback@theartfarm.com;pct=;ruf=mailto:dmarc-feedback@theartfarm.com'
        ),
        {
            v   => 'DMARC1',   p => 'reject',
            rua => 'mailto:dmarc-feedback@theartfarm.com',
            ruf => 'mailto:dmarc-feedback@theartfarm.com',
        },
        "parse, warns of invalid DMARC record format"
    );

    is_deeply(
        $pol->parse(
            'domain=tnpi.net;v=DMARC1;p=reject;rua=mailto:dmarc-feedback@theartfarm.com;pct=;ruf=mailto:dmarc-feedback@theartfarm.com'
        ),
        {
            v   => 'DMARC1',   p => 'reject', domain => 'tnpi.net',
            rua => 'mailto:dmarc-feedback@theartfarm.com',
            ruf => 'mailto:dmarc-feedback@theartfarm.com',
        },
        "parse, warns of invalid DMARC record format, with location"
    );

    $pol = $pol->parse('v=DMARC1');
    isa_ok( $pol, 'Mail::DMARC::Policy' );
    $expected = {
        v   => 'DMARC1'
    };
    is_deeply( $pol, $expected, 'parse');
}

sub test_is_valid_p {
    foreach my $p (qw/ none reject quarantine /) {
        ok( $pol->is_valid_p($p), "policy->is_valid_p, pos, $p" );
    }

    foreach my $p (qw/ other gibberish non-policy words /) {
        ok( !$pol->is_valid_p($p), "policy->is_valid_p, neg, $p" );
    }
}

sub test_is_valid_rf {
    foreach my $f (qw/ afrf iodef /) {
        ok( $pol->is_valid_rf($f), "policy->is_valid_rf, pos, $f" );
    }

    foreach my $f (qw/ ffrf i0def report /) {
        ok( !$pol->is_valid_rf($f), "policy->is_valid_rf, neg, $f" );
    }
}

sub test_is_valid {

    # empty policy
    my $pol = Mail::DMARC::Policy->new();
    eval { $pol->is_valid(); };
    chomp $@;
    ok( $@, "is_valid, $@" );

    eval { $pol = Mail::DMARC::Policy->new('v=DMARC1') };
    chomp $@;
    ok( $@, "is_valid, 1.4.1 meaningless, $@" );

    eval { $pol = Mail::DMARC::Policy->new('v=DMARC1\; p=reject\;') };
    ok( $pol, "is_valid, 1.4.3 extra backslashes" );

    eval { $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject; newtag=unknown') };
    ok( $pol, "is_valid, 1.4.4 unknown tag" );

    eval { $pol = Mail::DMARC::Policy->new('v=DMARC1; p=bogus') };
    chomp $@;
    ok( $@, "is_valid, 1.4.5 bogus p value, $@" );

    # policy, minimum
    $pol = Mail::DMARC::Policy->new( 'v=DMARC1; p=reject' );
    ok( $pol->is_valid, "is_valid, 1.4.2 smallest record" );

    # policy, min + defaults
    $pol->apply_defaults();
    ok( $pol->is_valid, "is_valid, pos, w/defaults" );

    # 9.6 policy discovery
    $pol = undef;
    eval { $pol = Mail::DMARC::Policy->new( v => 'DMARC1' ); };  # or diag $@;
    ok( !$pol, "is_valid, neg, missing p, no rua" );

    eval {
        $pol = Mail::DMARC::Policy->new(
            v   => 'DMARC1',
            rua => 'ftp://www.example.com'
        );
    };                                                           # or diag $@;
    ok( !$pol, "is_valid, neg, missing p, invalid rua" );

    $pol = undef;
    eval {
        $pol = Mail::DMARC::Policy->new(
            v   => 'DMARC1',
            rua => 'mailto:test@example.com'
        );
    };
    ok( $pol && $pol->is_valid, "is_valid, pos, implicit p=none w/rua" );
}

sub test_stringify {
    $pol = Mail::DMARC::Policy->new( 'v=DMARC1; p=reject' );
    ok($pol->stringify, 'v=DMARC1; p=reject');
}

sub handles_common_record_errors {

    foreach my $d (<DATA>) {
        chomp $d;
        my $pol = Mail::DMARC::Policy->new($d);

        eval { ok( $pol->is_valid(), "policy is valid: $d"); };
    }
}

# unhandled errors
#domain=caasco.ca;v=DMARC1;p=none;sp=none;rua=mailto:dmarc_agg@auth.returnpath.net;ruf=mailto:dmarc_afrf@auth.returnpath.net;rf=afrf;pct100
#domain=edm.groceryrun.com.au;v=dmarc1;p=none;rua=mailto:dmarc_feedback@inxmail.de&amp;amp;amp;amp;lt;dmarc_feedback@inxmail.de&amp;amp;amp;amp;gt
#domain=reply.myphotobook.de;v=DMARC1;p=reject;adkim=s;aspf=r;rf�rf;pct0
#domain=email.ex.kbhmaui.com;v=DMARC1;p=none;rua=mailto:dmarc-reports@email.ex.kbhmaui.com;pct=100;”

__DATA__
domain=accuquote.com;v=DMARC1;p=none;fo:0;adkim=r;aspf=r;sp=none;rua=mailto:accu_postmaster@accuquote.com
domain=targetselect.net;v=DMARC1;p=none;rua=mailto:postmaster@targetselect.net;ruf=mailto:postmaster@targetselect.net;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=1105insight.com;v=DMARC1;p=none;rua=mailto:postmaster@1105insight.com;ruf=mailto:postmaster@1105insight.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=borsheims.net;v=DMARC1;p=none;rua=mailto:postmaster@borsheims.net;ruf=mailto:postmaster@borsheims.net;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=consumersilver.com;v=DMARC1;p=none;rua=mailto:postmaster@consumersilver.com;ruf=mailto:postmaster@consumersilver.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=coppermail-usa.com;v=DMARC1;p=none;rua=mailto:postmaster@coppermail-usa.com;ruf=mailto:postmaster@coppermail-usa.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=eglancesender.com;v=DMARC1;p=none;rua=mailto:postmaster@eglancesender.com;ruf=mailto:postmaster@eglancesender.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=egroupconsumer.com;v=DMARC1;p=none;rua=mailto:postmaster@egroupconsumer.com;ruf=mailto:postmaster@egroupconsumer.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=eselectsender.com;v=DMARC1;p=none;rua=mailto:postmaster@eselectsender.com;ruf=mailto:postmaster@eselectsender.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=filemail.com;v=DMARC1;p=none;rua=mailto:admin@filemail.com;ruf=mailto:admin@filemail.com;fo:0;adkim=r;aspf=r
domain=fisherprograms.com;v=DMARC1;p=none;rua=mailto:postmaster@fisherprograms.com;ruf=mailto:postmaster@fisherprograms.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=mail-peninsula.com;v=DMARC1;p=none;rua=mailto:umesh@force24.co.uk;ruf=mailto:umesh@force24.co.uk;fo:0;adkim=r;aspf=r;pct=100;rf=afrf;ri=86000;sp=none
domain=sendergroup.com;v=DMARC1;p=none;rua=mailto:postmaster@sendergroup.com;ruf=mailto:postmaster@sendergroup.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=targetselection.com;v=DMARC1;p=none;rua=mailto:postmaster@targetselection.com;ruf=mailto:postmaster@targetselection.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=trondheim-redcross.no;v=DMARC1;p=none;rua=mailto:postmaster@trondheim-redcross.no;ruf=mailto:johess@trondheim-redcross.no;fo:0;adkim=r;aspf=r;pct=100;rf=afrf;ri=86400;sp=none
domain=vsender-2.com;v=DMARC1;p=none;rua=mailto:postmaster@vsender-2.com;ruf=mailto:postmaster@vsender-2.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=vsender-3.com;v=DMARC1;p=none;rua=mailto:postmaster@vsender-3.com;ruf=mailto:postmaster@vsender-3.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=wfyi.org;v=DMARC1;p=none;rua=mailto:dmarc1630@wfyi.org;ruf=mailto:dmarc1630@wfyi.org;fo:0;adkim=r;aspf=r;pct=100;rf=afrf;ri=86400;sp=none
domain=wk1business.com;v=DMARC1;p=none;rua=mailto:postmaster@wk1business.com;ruf=mailto:postmaster@wk1business.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=teogenes.com.br;v=DMARC1;p=quarantine;rua=mailto:retorno@teogenes.com.br;fo:1:d;adkim=r;aspf=r;rf=afrf;sp=quarantine
domain=wkcplatnium.com;v=DMARC1;p=none;rua=mailto:postmaster@wkcplatnium.com;ruf=mailto:postmaster@wkcplatnium.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=brightworksgroup.net;v=DMARC1;p=none;0;adkim=r;aspf=r
domain=bronzemail-usa.com;v=DMARC1;p=none;rua=mailto:postmaster@bronzemail-usa.com;ruf=mailto:postmaster@bronzemail-usa.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=driveconsumer.com;v=DMARC1;p=none;rua=mailto:postmaster@driveconsumer.com;ruf=mailto:postmaster@driveconsumer.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=econnect1.com;v=DMARC1;p=none;rua=mailto:postmaster@econnect1.com;ruf=mailto:postmaster@econnect1.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=esender1.com;v=DMARC1;p=none;rua=mailto:postmaster@esender1.com;ruf=mailto:postmaster@esender1.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=esender3.com;v=DMARC1;p=none;rua=mailto:postmaster@esender3.com;ruf=mailto:postmaster@esender3.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=lns.com;v=DMARC1;p=none;rua=mailto:dmarc@lns.com;ruf=mailto:dmarc@lns.com;0;adkim=r;aspf=r;pct=100;rf=afrf;ri=86400;sp=none
domain=my-dear-lady.com;v=DMARC1;p=none;rua=mailto:postmaster@my-dear-lady.com;ruf=mailto:postmaster@my-dear-lady.com;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=theluxurycloset.info;v=DMARC1;p=reject;adkim=s;aspf=r;rf=afrf;;pct=100
domain=newsletter.ironpony.net;v=DMARC1;p=none;rua=mailto:postmaster@newsletter.ironpony.net;ruf=mailto:postmaster@newsletter.ironpony.net;adkim=r;aspf=r;pct=100;rf:afrf;ri=86400;sp=none
domain=cmnet.org;v=DMARC1;p=none;sp=none;rua=mailto:postmaster@cmnet.org!10m;;pct=100;ri=86400
domain=coachingcompass.com;v=DMARC1;p=quarantine;rua=mailto:dan@darau.com;ruf=mailto:dan@darau.com;1:d:s;adkim=r;aspf=r;rf=afrf;sp=quarantine
domain=genetex.com;v=DMARC1;p=none;sp-none;rua=mailto:postmaster@genetex.com!1m;ruf=mailto:postmaster@genetex.com!1m;rf=afrf;pct=100;ri=86400
