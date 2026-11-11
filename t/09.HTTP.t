use strict;
use warnings;

use Data::Dumper;
use Net::DNS::Resolver::Mock;
use Test::More;
use Test::Output;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';

foreach my $req ( 'DBD::SQLite 1.31', 'JSON', 'Net::Server::HTTP' ) {
    eval "use $req";
    if ($@) {
        plan( skip_all => "$req not available" );
        exit;
    }
};

my $resolver = new Net::DNS::Resolver::Mock();
$resolver->zonefile_parse(join("\n",
'tnpi.net.                         600 A   66.128.51.170',
'_dmarc.tnpi.net.                  600 TXT "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@theartfarm.com; ruf=mailto:dmarc-feedback@theartfarm.com; pct=100"',
#'tnpi.net.                         600 MX  10 mail.theartfarm.com.',
''));

my $mod = 'Mail::DMARC::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

my $r = Mail::DMARC::HTTP::serve_validator('', $resolver);
ok($r eq 'missing POST data', "serve_validator, missing POST data");

$r = Mail::DMARC::HTTP::serve_validator('foo', $resolver);
like($r, qr/expected/, "serve_validator, invalid JSON");

$r = Mail::DMARC::HTTP::serve_validator('{"foo":"bar"}', $resolver);
like($r, qr/no header_from/, "serve_validator, missing header_from");

$r = Mail::DMARC::HTTP::serve_validator('{"header_from":"tnpi.net"}', $resolver);
like($r, qr/"spf":""/, "serve_validator, missing SPF");
like($r, qr/"dkim":"fail"/, "serve_validator, missing DKIM");

$r = Mail::DMARC::HTTP::serve_validator('{"header_from":"tnpi.net","spf":[{"domain":"tnpi.net","scope":"mfrom","result":"pass"}]}', $resolver);
like($r, qr/"spf":"pass"/, "serve_validator, pass SPF");
like($r, qr/"dkim":"fail"/, "serve_validator, missing DKIM");

$r = Mail::DMARC::HTTP::serve_validator('{"header_from":"tnpi.net","dkim":[{"domain":"tnpi.net","selector":"mar2013","result":"pass"}]}', $resolver);
like($r, qr/"spf":""/, "serve_validator, missing SPF");
like($r, qr/"dkim":"pass"/, "serve_validator, pass DKIM");

__post_max();

sub __post_max {
    is( Mail::DMARC::HTTP::post_max(), 10 * 1024 * 1024,
        'post_max, default when no config is loaded' );

    local $Mail::DMARC::HTTP::report = Mail::DMARC::PurePerl->new->report;
    $Mail::DMARC::HTTP::report->config->{http}{post_max} = 4096;
    is( Mail::DMARC::HTTP::post_max(), 4096, 'post_max, from config' );

    for my $bogus ( '', 'lots', '-1', '0', '00', '01', '007', ' 8', '8 ', '1e6' ) {
        $Mail::DMARC::HTTP::report->config->{http}{post_max} = $bogus;
        is( Mail::DMARC::HTTP::post_max(), 10 * 1024 * 1024,
            "post_max, falls back on '$bogus'" );
    }

    # read_post_body reports an oversized body as undef so that
    # serve_validator can tell it apart from a request with no body at all
    $Mail::DMARC::HTTP::report->config->{http}{post_max} = 16;
    local $ENV{CONTENT_LENGTH} = 17;
    my ( undef, $over ) = with_stdin( 'x' x 17,
        sub { Mail::DMARC::HTTP::read_post_body() } );
    is( $over, undef, 'read_post_body, undef over post_max' );

    $Mail::DMARC::HTTP::report->config->{http}{post_max} = 128;
    my $r = capture_validator( 129, $resolver );
    like( $r, qr/larger than post_max of 128 bytes/,
        'serve_validator, refuses over post_max' );

    __discard_post_body();
    __warn_unusable_post_max();
}

# an oversized body has to come off the wire before the error is written, or
# the close answers RST and the client never sees it
sub __discard_post_body {
    $Mail::DMARC::HTTP::report->config->{http}{post_max} = 1024;
    my $body = 'x' x 2000;

    my ($left) = with_stdin( $body,
        sub { Mail::DMARC::HTTP::discard_post_body( length $body ) } );
    is( length $left, 0, 'discard_post_body, drains the body' );

    # past twice post_max we leave it unread and let the connection reset
    ($left) = with_stdin( $body,
        sub { Mail::DMARC::HTTP::discard_post_body(3000) } );
    is( length $left, 2000, 'discard_post_body, leaves a huge body unread' );
}

sub __warn_unusable_post_max {
    for my $bad ( '0', '00', '01', '20M', '-1', '1e6' ) {
        $Mail::DMARC::HTTP::report->config->{http}{post_max} = $bad;
        stderr_like { Mail::DMARC::HTTP::warn_unusable_post_max() }
            qr/post_max '\Q$bad\E' is not a byte count/,
            "warn_unusable_post_max, warns on '$bad'";
    }
    for my $ok ( undef, '', '4096' ) {
        $Mail::DMARC::HTTP::report->config->{http}{post_max} = $ok;
        stderr_is { Mail::DMARC::HTTP::warn_unusable_post_max() } '',
            'warn_unusable_post_max, silent on ' . ( $ok // 'undef' );
    }
}

# Anything that reads a POST body must be handed an in-memory STDIN. The real
# one is a terminal when this file is run by hand but a pipe under prove, where
# a read of it never returns. Returns what the body left unread, then $code's
# return values.
sub with_stdin {
    my ( $body, $code ) = @_;
    open my $saved, '<&', \*STDIN or die $!;
    close STDIN;
    open STDIN, '<', \$body or die $!;
    my @rv = $code->();
    my $left = do { local $/; <STDIN> };
    close STDIN;
    open STDIN, '<&', $saved or die $!;
    return ( $left // '', @rv );
}

sub capture_validator {
    my ( $content_length, $res ) = @_;
    local $ENV{CONTENT_LENGTH} = $content_length;
    my $out;
    open my $fh, '>', \$out or die $!;
    my $old = select $fh;    ## no critic (ProhibitOneArgSelect)
    my ( undef, $r )
        = with_stdin( '', sub { Mail::DMARC::HTTP::serve_validator( undef, $res ) } );
    select $old;             ## no critic (ProhibitOneArgSelect)
    close $fh;
    return $r;
}

# agg_params guards the aggregate report views: it coerces what it recognizes
# and silently drops everything else, so a hand-built query string cannot
# reach the store with junk in it.
my %defaulted = Mail::DMARC::HTTP::agg_params( {} );
ok( $defaulted{since} && $defaulted{until}, "agg_params, window defaults" );
cmp_ok( $defaulted{until} - $defaulted{since}, '==', 30 * 86400,
    "agg_params, default window is 30 days" );

my %explicit = Mail::DMARC::HTTP::agg_params(
    { since => '1700000000', until => '1700086400' } );
cmp_ok( $explicit{since}, '==', 1700000000, "agg_params, since honored" );
cmp_ok( $explicit{until}, '==', 1700086400, "agg_params, until honored" );

foreach my $junk ( 'abc', '1e9', '2024-01-01', '12; DROP TABLE report',
    '99999999999999' )
{
    my %args = Mail::DMARC::HTTP::agg_params( { since => $junk } );
    cmp_ok( $args{since}, '==', $args{until} - 30 * 86400,
        "agg_params, rejects since=$junk" );
}

my %paged = Mail::DMARC::HTTP::agg_params( { start => '10', length => '25' } );
cmp_ok( $paged{start},  '==', 10, "agg_params, start" );
cmp_ok( $paged{length}, '==', 25, "agg_params, length" );

my %strs = Mail::DMARC::HTTP::agg_params( {
        from_domain => 'example.com',
        author      => 'google.com',
        source_ip   => '192.0.2.1',
        sort_col    => 'messages',
        empty       => '',
        unknown     => 'nope',
    } );
is( $strs{from_domain}, 'example.com', "agg_params, from_domain" );
is( $strs{source_ip},   '192.0.2.1',   "agg_params, source_ip" );
is( $strs{sort_col},    'messages',    "agg_params, sort_col" );
ok( !exists $strs{unknown}, "agg_params, drops unknown params" );
ok( !exists $strs{empty},   "agg_params, drops empty params" );

my %toolong = Mail::DMARC::HTTP::agg_params( { from_domain => 'a' x 254 } );
ok( !exists $toolong{from_domain}, "agg_params, drops oversized string" );

my %blank = Mail::DMARC::HTTP::agg_params( { from_domain => undef } );
ok( !exists $blank{from_domain}, "agg_params, drops undef" );

# serve_file resolves a request path under the share directory. Only names
# matching the viewer's own assets may reach the filesystem: a path that can
# name a parent directory reads any .js, .css, .html or .json file the daemon
# can open, which on a mail server is a good deal more than the viewer.
my @traversals = (
    '/dmarc/../../META.json',
    '/dmarc/js/../../../META.json',
    '/dmarc/./../META.json',
    '/dmarc/..%2f..%2fMETA.json',
    '/dmarc/....//META.json',
    '/dmarc/.hidden.js',
    '/dmarc//index.html',
);

foreach my $path (@traversals) {
    my $output = '';
    {
        local *STDOUT;
        open STDOUT, '>', \$output or die "cannot capture STDOUT: $!";
        Mail::DMARC::HTTP::serve_file($path);
    }
    unlike( $output, qr/"abstract"/,
        "serve_file, no file served outside share for $path" );
    like( $output, qr/no such file/,
        "serve_file, rejects $path" );
}

# the viewer's own assets still resolve, including one in a subdirectory
my %assets = (
    '/dmarc/index.html'  => qr{text/html},
    '/dmarc/dmarc.css'   => qr{text/css},
    '/dmarc/js/app.js'   => qr{application/javascript},
);

foreach my $path ( sort keys %assets ) {
    my $output = '';
    {
        local *STDOUT;
        open STDOUT, '>', \$output or die "cannot capture STDOUT: $!";
        Mail::DMARC::HTTP::serve_file($path);
    }
    like( $output, $assets{$path}, "serve_file, serves $path" );
    cmp_ok( length $output, '>', 100, "serve_file, $path has content" );
}

my $unknown = '';
{
    local *STDOUT;
    open STDOUT, '>', \$unknown or die "cannot capture STDOUT: $!";
    Mail::DMARC::HTTP::serve_file('/dmarc/mail-dmarc.ini');
}
like( $unknown, qr/not recognized/,
    'serve_file, rejects an extension with no mime type' );

test_dispatch();

done_testing();

sub dispatch {
    my ( $path, $query, $post ) = @_;
    local $ENV{QUERY_STRING}   = $query // '';
    local $ENV{CONTENT_LENGTH} = length( $post // '' );
    local $SIG{__WARN__} = sub { warn @_ if $_[0] !~ /^path: / };
    my $out = '';
    with_stdin(
        $post // '',
        sub {
            local *STDOUT;
            open STDOUT, '>', \$out or die "cannot capture STDOUT: $!";
            Mail::DMARC::HTTP::dmarc_dispatch( { request_info => { request_path => $path } } );
        }
    );
    my ( $head, $body ) = split /\n\n/, $out, 2;
    my ($type) = $head =~ /^Content-Type: (\S+)/m;
    my $json = $type && $type eq 'application/json' ? eval { decode_json($body) } : undef;
    return ( $type, $json, $body );
}

sub test_dispatch {
    local $ENV{MAIL_DMARC_CONFIG_FILE} = 't/mail-dmarc.ini';
    unlink 't/reports-test.sqlite';
    require Mail::DMARC::Report::Receive;
    Mail::DMARC::Report::Receive->new->from_file('t/fixtures/test_dmarc.xml');
    local $Mail::DMARC::HTTP::report = Mail::DMARC::Report->new;

    my $window = 'since=1609000000&until=1610000000';

    my ( $type, $json ) = dispatch('/dmarc/json/report');
    is( $type, 'application/json', 'dispatch, report list is JSON' );
    is( $json->{data}[0]{uuid}, '1234567890', 'dispatch, report list has the stored report' );
    my $rid = $json->{data}[0]{rid};

    ( undef, $json ) = dispatch( '/dmarc/json/row', "rid=$rid" );
    is( $json->{data}[0]{source_ip}, '1.2.3.4', 'dispatch, row has the record' );

    ( undef, $json ) = dispatch('/dmarc/json/domains');
    is( $json->{data}[0]{domain}, 'example.com', 'dispatch, domains lists the policy domain' );

    ( undef, $json ) = dispatch( '/dmarc/json/summary', $window );
    is( $json->{current}{messages}, 1, 'dispatch, summary counts the message' );

    ( undef, $json ) = dispatch( '/dmarc/json/timeseries', $window );
    is( $json->{data}[0]{messages}, 1, 'dispatch, timeseries has the day' );

    ( undef, $json ) = dispatch( '/dmarc/json/sources', $window );
    is( $json->{data}[0]{messages}, 1, 'dispatch, sources has the source' );

    ( undef, $json ) = dispatch( '/dmarc/json/source', "$window&source_ip=1.2.3.4" );
    is( $json->{source_ip}, '1.2.3.4', 'dispatch, source detail' );

    ( undef, $json ) = dispatch( '/dmarc/json/source', $window );
    like( $json->{err}, qr/missing source_ip/, 'dispatch, store errors are returned as JSON' );

    ( $type, $json ) = dispatch( '/dmarc/json/validate', '',
        '{"header_from":"tnpi.net","spf":[{"domain":"tnpi.net","scope":"mfrom","result":"pass"}]}' );
    is( $type, 'application/json', 'dispatch, validate reads the POST body' );

    my $body;
    ( $type, undef, $body ) = dispatch('/dmarc/dmarc.css');
    is( $type, 'text/css', 'dispatch, serves a stylesheet' );

    foreach my $path ( '', '/dmarc/', '/not/a/route' ) {
        ( $type, undef, $body ) = dispatch($path);
        like( $body, qr/<title>DMARC reports<\/title>/,
            "dispatch, '$path' serves the viewer" );
    }

    unlink 't/reports-test.sqlite';
}
