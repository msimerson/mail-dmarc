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
        fo    => [qw/ 0 1 d s D S /],
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

    eval { $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject; rua=a@dmarc-qa.com;') };
    ok( $pol, "is_valid, 1.4.6 missing mailto" );

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
