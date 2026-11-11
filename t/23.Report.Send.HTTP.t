use strict;
use warnings;

use File::Temp ();
use HTTP::Tiny;
use IO::Compress::Gzip qw(gzip);
use IO::Socket::INET;
use IO::Uncompress::Gunzip qw(gunzip);
use Net::DNS::Resolver::Mock;
use POSIX ();
use Socket ();
use Storable ();
use Test::Exception;
use Test::More;
use URI;

$ENV{MAIL_DMARC_CONFIG_FILE} = 't/mail-dmarc.ini';

use lib 'lib';
use Test::File::ShareDir -share => { -dist => { 'Mail-DMARC' => 'share' } };

my $mod = 'Mail::DMARC::Report::Send::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

throws_ok { $http->post( { report => 'x' } ) } qr/missing uri/, 'post requires a uri';
throws_ok { $http->post( { uri => 'http://127.0.0.1/' } ) } qr/missing report/,
    'post requires a report';

test_public_address();
test_refused_destinations();

SKIP: {
    skip 'forked test HTTP server is unreliable on Windows', 1 if $^O eq 'MSWin32';
    test_post();
    test_post_refused();
    test_post_unreachable();
    test_response_bodies();
    test_peer_pinning();
    test_ignores_proxy_env();
    test_https();
    test_sender();
}

done_testing();
exit;

# Accepts one request, answers it with $status, and hands back what it got.
sub one_shot_server {
    my ( $status, %reply ) = @_;
    my $body    = $reply{body} // '';
    my $headers = join '', map {"$_\r\n"} @{ $reply{headers} // [] };
    my $listen = IO::Socket::INET->new(
        Listen    => 1,
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Proto     => 'tcp',
        ReuseAddr => 1,
    ) or die "listen: $!";
    my $capture = File::Temp->new;

    my $pid = fork // die "fork: $!";
    if ( !$pid ) {
        alarm 20;
        my $c = $listen->accept or POSIX::_exit(1);
        if ( $reply{tls} ) {
            IO::Socket::SSL->start_SSL(
                $c,
                SSL_server => 1,
                SSL_cert   => $reply{tls}[0],
                SSL_key    => $reply{tls}[1],
            ) or POSIX::_exit(2);
        }
        my %req = ( headers => {} );
        ( $req{request_line} = <$c> ) =~ s/\r\n\z//;
        while ( my $line = <$c> ) {
            last if $line eq "\r\n";
            $line =~ s/\r\n\z//;
            my ( $k, $v ) = split /:\s*/, $line, 2;
            $req{headers}{ lc $k } = $v;
        }
        my $want = $req{headers}{'content-length'} // 0;
        $req{body} = '';
        while ( length $req{body} < $want ) {
            read( $c, my $chunk, $want - length $req{body} ) or last;
            $req{body} .= $chunk;
        }
        printf {$c} "HTTP/1.1 %s Test\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s",
            $status, $headers, length $body, $body;
        close $c;
        Storable::nstore( \%req, "$capture" );
        POSIX::_exit(0);    # skip END blocks, which belong to the parent's Test::More
    }

    my $url = sprintf 'http://127.0.0.1:%d/dmarc', $listen->sockport;
    close $listen;
    my $received = sub {
        waitpid $pid, 0;
        return -s "$capture" ? Storable::retrieve("$capture") : undef;
    };
    return ( $url, $received, $capture );
}

sub test_post {
    my ( $url, $received ) = one_shot_server(200);
    my $xml = '<feedback><report_metadata/></feedback>';
    gzip( \$xml => \my $gz ) or die;

    my $res = $http->post(
        {   uri      => URI->new($url),
            report   => $gz,
            subject  => 'Report Domain: example.com Submitter: example-test.com Report-ID: abc',
            filename => 'example-test.com!example.com!1!2!abc.xml.gz',
        }
    );
    ok( $res->{success}, 'post, 200 is success' );

    my $req = $received->();
    is( $req->{request_line}, 'POST /dmarc HTTP/1.1', 'post, POSTs to the rua path' );
    is( $req->{headers}{'content-type'}, 'application/gzip', 'post, gzip content type' );
    is( $req->{headers}{'content-disposition'},
        'attachment; filename="example-test.com!example.com!1!2!abc.xml.gz"',
        'post, report filename' );
    is( $req->{headers}{subject},
        'Report Domain: example.com Submitter: example-test.com Report-ID: abc',
        'post, report Subject' );
    like( $req->{headers}{'user-agent'}, qr{^Mail-DMARC/}, 'post, identifies itself' );
    is( $req->{body}, $gz, 'post, sends the report unaltered' );
}

sub test_post_refused {
    my ( $url, $received ) = one_shot_server(503);
    my $res = $http->post( { uri => $url, report => 'gz' } );
    ok( !$res->{success}, 'post, 503 is not success' );
    is( $res->{status}, 503, 'post, returns the status' );
    $received->();
}

sub test_public_address {
    my %public = (
        '8.8.8.8'               => 1,
        '172.32.0.1'            => 1,
        '2001:4860:4860::8888'  => 1,
        '64:ff9b::808:808'      => 1,
        '0.0.0.0'               => 0,
        '10.1.2.3'              => 0,
        '100.64.0.1'            => 0,
        '127.0.0.1'             => 0,
        '169.254.169.254'       => 0,
        '172.31.255.255'        => 0,
        '192.168.1.1'           => 0,
        '198.51.100.7'          => 0,
        '224.0.0.1'             => 0,
        '255.255.255.255'       => 0,
        '::'                    => 0,
        '::1'                   => 0,
        '::ffff:10.0.0.1'       => 0,
        '64:ff9b::a00:1'        => 0,
        '64:ff9b:1::a00:1'      => 0,
        'fec0::1'               => 0,
        'fd00::1'               => 0,
        'fe80::1'               => 0,
        'ff02::1'               => 0,
        '2001:db8::1'           => 0,
    );
    for my $ip ( sort keys %public ) {
        my $packed = Socket::inet_pton( $ip =~ /:/ ? Socket::AF_INET6() : Socket::AF_INET(), $ip );
        is( !!$mod->can('is_public_address')->($packed), !!$public{$ip},
            "is_public_address, $ip" );
    }
    is( $http->public_peer('8.8.8.8'), '8.8.8.8', 'public_peer, a public address' );
}

sub test_refused_destinations {
    for my $uri ( 'http://10.0.0.1/dmarc', 'https://[::1]/dmarc', 'http://localhost/dmarc' ) {
        my $res = $http->post( { uri => $uri, report => 'gz' } );
        ok( !$res->{success}, "post, $uri is refused" );
        is( $res->{status}, 599, "post, $uri is refused as a 599" );
        like( $res->{content}, qr/non-public address/, "post, $uri says why" );
    }

    my $res = $http->post( { uri => 'http://no-such-host.invalid/dmarc', report => 'gz' } );
    like( $res->{content}, qr/unable to resolve no-such-host\.invalid/,
        'post, an unresolvable host is refused' );

    ok( $http->is_allowed_host('127.0.0.1'), 'http_allow_hosts permits a listed host' );
    ok( !$http->is_allowed_host('10.0.0.1'), 'http_allow_hosts permits only listed hosts' );
}

sub test_response_bodies {
    my ( $url, $received ) = one_shot_server( 200, body => 'x' x 100_000 );
    my $res = $http->post( { uri => $url, report => 'gz' } );
    ok( $res->{success}, 'post, a large success body is still success' );
    is( $res->{content}, '', 'post, a success body is discarded' );
    $received->();

    ( $url, $received ) = one_shot_server( 500, body => 'y' x 100_000 );
    $res = $http->post( { uri => $url, report => 'gz' } );
    ok( !$res->{success}, 'post, a large error body is not success' );
    cmp_ok( length $res->{content}, '<', 10_000, 'post, an error body is bounded' );
    $received->();

    ( $url, $received ) = one_shot_server( 303, headers => ['Location: http://10.0.0.1/'] );
    $res = $http->post( { uri => $url, report => 'gz' } );
    is( $res->{status}, 303, 'post, redirects are not followed' );
    $received->();
}

# Stands in for DNS: the rua host is not allowlisted and "resolves" to the
# local test server, so delivery depends on post connecting to the checked peer.
sub post_pinned_to_localhost {
    my ( $url, $host, $client ) = @_;
    my $uri = URI->new($url);
    $uri->host($host);
    $uri->scheme('https') if $client && $client eq 'https';
    no warnings 'redefine';
    local *Mail::DMARC::Report::Send::HTTP::public_peer = sub { return '127.0.0.1' };
    return ( $http->post( { uri => "$uri", report => 'gz' } ), $uri->port );
}

sub test_peer_pinning {
    ok( !$http->is_allowed_host('reports.example'), 'pinning, the host is not allowlisted' );
    my ( $url, $received ) = one_shot_server(200);
    my ( $res, $port ) = post_pinned_to_localhost( $url, 'reports.example' );
    ok( $res->{success}, 'pinning, delivered to the checked peer' );
    my $req = $received->();
    is( $req->{headers}{host}, "reports.example:$port", 'pinning, Host is the rua host' );
}

sub test_ignores_proxy_env {
    my $closed = IO::Socket::INET->new( Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0 )
        or die "listen: $!";
    my $proxy = sprintf 'http://127.0.0.1:%d/', $closed->sockport;
    close $closed;

    local @ENV{qw( http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY )}
        = ($proxy) x 6;
    local $ENV{no_proxy};
    my ( $url, $received ) = one_shot_server(200);
    my $res = $mod->new->post( { uri => $url, report => 'gz' } );
    ok( $res->{success}, 'proxy, environment proxies are not used' );
    ok( $received->(), 'proxy, the rua received the POST directly' );
}

sub test_https {
    SKIP: {
        skip 'https tests need IO::Socket::SSL 1.56 and Net::SSLeay 1.49', 6
            if !eval {
            require IO::Socket::SSL;
            IO::Socket::SSL->VERSION(1.56);
            require IO::Socket::SSL::Utils;
            HTTP::Tiny->can_ssl;
            };

        my $create = \&IO::Socket::SSL::Utils::CERT_create;
        my ( $ca_cert, $ca_key )
            = $create->( CA => 1, subject => { commonName => 'Mail-DMARC test CA' } );
        my $issued_for = sub {
            my ( $name, $issuer ) = @_;
            return [
                $create->(
                    subject         => { commonName => $name },
                    subjectAltNames => [ [ DNS => $name ] ],
                    purpose         => 'server',
                    ( $issuer ? ( issuer => $issuer ) : () ),
                )
            ];
        };
        my $ca_file = File::Temp->new( SUFFIX => '.pem' );
        print {$ca_file} IO::Socket::SSL::Utils::PEM_cert2string($ca_cert);
        close $ca_file;
        local $ENV{SSL_CERT_FILE} = "$ca_file";

        my %case = (
            trusted  => [ $issued_for->( 'reports.example', [ $ca_cert, $ca_key ] ), 1 ],
            mismatch => [ $issued_for->( 'other.example',   [ $ca_cert, $ca_key ] ), 0 ],
            untrusted => [ $issued_for->('reports.example'), 0 ],
        );
        for my $name (qw( trusted mismatch untrusted )) {
            my ( $tls, $delivers ) = @{ $case{$name} };
            my ( $url, $received ) = one_shot_server( 200, tls => $tls );
            my ($res) = post_pinned_to_localhost( $url, 'reports.example', 'https' );
            my $req = $received->();
            if ($delivers) {
                ok( $res->{success}, "https, $name certificate delivers to the pinned peer" );
                like( $req->{headers}{host}, qr/^reports\.example:/, "https, $name, Host is the rua host" );
            }
            else {
                is( $res->{status}, 599, "https, $name certificate is refused" ) or diag $res->{content};
                ok( !$req, "https, $name, no report is sent" );
            }
        }
    }
}

sub test_post_unreachable {
    my $closed = IO::Socket::INET->new( Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0 )
        or die "listen: $!";
    my $port = $closed->sockport;
    close $closed;

    my $res = $http->post( { uri => "http://127.0.0.1:$port/dmarc", report => 'gz' } );
    ok( !$res->{success}, 'post, connection refused is not success' );
    is( $res->{status}, 599, 'post, connection failure is 599' );
}

sub queue_report_for {
    my ($rua) = @_;
    unlink 't/reports-test.sqlite';

    my $resolver = Net::DNS::Resolver::Mock->new;
    $resolver->zonefile_parse( join "\n",
        'httprua.dmarctest.net.                         600 MX  10 mail.httprua.dmarctest.net.',
        qq{_dmarc.httprua.dmarctest.net.                  600 TXT "v=DMARC1; p=reject; rua=$rua"},
        'httprua.dmarctest.net._report._dmarc.127.0.0.1. 600 TXT "v=DMARC1"',
        '' );

    require Mail::DMARC::PurePerl;
    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    $dmarc->set_fake_time( time - 86400 );
    $dmarc->init();
    $dmarc->source_ip('192.0.2.1');
    $dmarc->envelope_to('example-test.com');
    $dmarc->envelope_from('httprua.dmarctest.net');
    $dmarc->header_from('httprua.dmarctest.net');
    $dmarc->dkim( [] );
    $dmarc->spf( [ { domain => 'httprua.dmarctest.net', scope => 'mfrom', result => 'pass' } ] );
    $dmarc->validate;
    $dmarc->save_aggregate;
    $dmarc->set_fake_time( time + 86400 );
}

sub reports_queued {
    require Mail::DMARC::Report;
    return scalar @{ Mail::DMARC::Report->new->store->backend->get_report->{data} };
}

sub test_sender {
    require Mail::DMARC::Report::Sender;

    my ( $url, $received ) = one_shot_server(200);
    queue_report_for($url);
    is( reports_queued(), 1, 'sender, a report for an http rua is queued' );

    my $sender = Mail::DMARC::Report::Sender->new;
    lives_ok { $sender->run } 'sender, run completes';

    my $req = $received->();
    ok( $req, 'sender, POSTs the report to the http rua' ) or return;
    gunzip( \$req->{body} => \my $xml ) or die "gunzip failed";
    like( $xml, qr{<domain>httprua\.dmarctest\.net</domain>}, 'sender, POST body is the report' );
    like( $req->{headers}{subject}, qr/^Report Domain: httprua\.dmarctest\.net Submitter: example-test\.com/,
        'sender, POST carries the report Subject' );
    is( reports_queued(), 0, 'sender, a delivered report is retired' );

    ( $url, $received ) = one_shot_server(500);
    queue_report_for($url);
    lives_ok { Mail::DMARC::Report::Sender->new->run } 'sender, a refused POST does not die';
    ok( $received->(), 'sender, the refused POST was attempted' );
    is( reports_queued(), 0, 'sender, a refused report is retired like a refused email' );

    unlink 't/reports-test.sqlite';
}
