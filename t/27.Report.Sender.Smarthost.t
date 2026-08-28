use strict;
use warnings;

use Test::More;
use Test::Exception;
use File::Temp qw(tempfile);
use Net::DNS::Resolver::Mock;

# Pin the config: an installation with a discoverable mail-dmarc.ini would
# otherwise point these at a real report store.
$ENV{MAIL_DMARC_CONFIG_FILE} = 't/mail-dmarc.ini';

use lib 'lib';
use Mail::DMARC::PurePerl;
use Mail::DMARC::Report::Sender;
use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

my $resolver = Net::DNS::Resolver::Mock->new();
$resolver->zonefile_parse(join("\n",
'fastmaildmarc.com.        600 MX  10 in1-smtp.messagingengine.com.',
'_dmarc.fastmaildmarc.com. 600 TXT "v=DMARC1; p=reject; rua=mailto:rua@fastmaildmarc.com"',
''));

sub sender_for {
    my (%smtp) = @_;
    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    my $report = $dmarc->report;
    $report->config->{smtp}{smarthost} = 'relay.example.com';
    $report->config->{smtp}{$_} = $smtp{$_} foreach keys %smtp;
    return ( Mail::DMARC::Report::Sender->new, $report );
}

sub transports_for {
    my ( $sender, $report ) = sender_for(@_);
    return $sender->get_transports_for( { report => $report } );
}

sub routes {
    return join ' -> ', map { sprintf '%s/%s', $_->port, ( $_->ssl || 'none' ) }
        transports_for(@_);
}

subtest 'a smart host alone tries relay, submission, then cleartext' => sub {
    is( routes(), '25/maybestarttls -> 587/starttls -> 25/none',
        'encrypted first, cleartext rather than not delivering' );
    is( routes( smartport => '', smartssl => '', smartuser => '',
            smartpass => '' ),
        '25/maybestarttls -> 587/starttls -> 25/none',
        'empty settings are not settings' );
};

subtest 'credentials never reach a mode that can authenticate in clear' => sub {

    # maybestarttls skips STARTTLS when the host does not advertise it and
    # authenticates anyway, so reading the attribute is not enough: the mode
    # itself has to guarantee encryption.
    my %encrypts = map { $_ => 1 } qw/ starttls ssl /;

    foreach my $case (
        [ 'ladder',    {} ],
        [ 'port 25',   { smartport => 25 } ],
        [ 'port 2525', { smartport => 2525 } ],
        [ 'port 587',  { smartport => 587 } ],
        )
    {
        my ( $name, $extra ) = @$case;
        my @t = transports_for(
            smartuser => 'u', smartpass => 'p', %$extra );
        is( scalar( grep { !$encrypts{ $_->ssl // q{} } } @t ), 0,
            "$name offers only modes that always encrypt" );
    }

    # the operator can still ask for one
    is( routes( smartuser => 'u', smartpass => 'p', smartssl => 'none' ),
        '25/none', 'unless they say so' );
};

subtest 'a password without a username is not credentials' => sub {
    is( routes( smartpass => 'p' ),
        '25/maybestarttls -> 587/starttls -> 25/none',
        'the unauthenticated ladder is used' );
};

subtest 'a port is taken as given' => sub {
    is( routes( smartport => 25 ),   '25/maybestarttls',  'relay' );
    is( routes( smartport => 2525 ), '2525/maybestarttls', 'anything else' );
};

subtest 'the submission ports imply their TLS' => sub {
    is( routes( smartport => 465 ), '465/ssl',      'smtps' );
    is( routes( smartport => 587 ), '587/starttls', 'submission' );
};

subtest 'smartssl governs TLS' => sub {
    is( routes( smartssl => 'ssl' ),           '465/ssl',           'smtps' );
    is( routes( smartssl => 'starttls' ),      '25/starttls',       'starttls' );
    is( routes( smartssl => 'maybestarttls' ), '25/maybestarttls',  'opportunistic' );
    is( routes( smartssl => 'none' ),          '25/none',           'plaintext' );
    is( routes( smartssl => '  SSL  ' ),       '465/ssl',           'case and space' );

    is( routes( smartssl => 'none', smartport => 587 ), '587/none',
        'and overrides what the port would imply' );
    is( routes( smartssl => 'ssl', smartport => 10465 ), '10465/ssl',
        'while the port is still taken as given' );
};

subtest 'credentials try smtps, then submission, then the relay port' => sub {
    is( routes( smartuser => 'u', smartpass => 'p' ),
        '465/ssl -> 587/starttls -> 25/starttls', 'all three routes' );

    my @t = transports_for( smartuser => 'u', smartpass => 'p' );
    is( scalar( grep { $_->sasl_username eq 'u' } @t ), 3,
        'credentials on every route' );

    is( routes( smartuser => 'u', smartpass => 'p', smartport => 587 ),
        '587/starttls', 'a port still pins one route' );
    is( routes( smartuser => 'u', smartpass => 'p', smartssl => 'none' ),
        '25/none', 'so does smartssl, private networks included' );
};

subtest 'an unusable smartssl is refused, not guessed at' => sub {
    foreach my $value (qw/ tls yes secure starttls! 1 /) {
        throws_ok { routes( smartssl => $value ) }
            qr/unknown smtp.smartssl/, "smartssl '$value' croaks";
    }
};

subtest 'the route that worked is the only one tried next time' => sub {
    my ( $sender, $report ) = sender_for( smartuser => 'u', smartpass => 'p' );

    my @first = $sender->get_transports_for( { report => $report } );
    cmp_ok( scalar @first, '==', 3, 'three routes to begin with' );

    $sender->keep_smarthost_route( $first[2] );

    my @next = $sender->get_transports_for( { report => $report } );
    cmp_ok( scalar @next, '==', 1, 'the dead route is not offered again' );
    cmp_ok( $next[0]->port, '==', 25, 'and the working one is kept' );

    $sender->keep_smarthost_route(
        Email::Sender::Transport::SMTP::Persistent->new(
            { host => 'elsewhere.example.com', port => 25 } ) );
    cmp_ok( scalar @{ $sender->{smarthost} }, '==', 1,
        'a transport from elsewhere does not replace the list' );
};

subtest 'a transport supplied to the constructor still wins' => sub {
    my ( undef, $report ) = sender_for();
    my $canned = Email::Sender::Transport::SMTP::Persistent->new(
        { host => 'given.example.com', port => 2525 } );
    my $sender = Mail::DMARC::Report::Sender->new( { smarthost => $canned } );

    my @t = $sender->get_transports_for( { report => $report } );
    cmp_ok( scalar @t, '==', 1, 'the given transport is used' );
    is( $t[0]->host, 'given.example.com', 'and nothing else is built' );
};

subtest 'a custom transports class is left to its own routing' => sub {
    my ( $fh, $ini ) = tempfile( SUFFIX => '.ini' );
    print {$fh} <<"EO_INI";
[organization]
domain   = dmarc-test.example.net
org_name = Test
email    = dmarc\@example.com

[report_store]
backend = SQL
dsn     = dbi:SQLite:dbname=t/reports-test.sqlite

[smtp]
hostname   = mail.example.com
smarthost  = relay.example.com
smartssl   = tls
transports = Mail::DMARC::Test::Transport
EO_INI
    close $fh;

    unlink 't/reports-test.sqlite' if -e 't/reports-test.sqlite';
    local $ENV{MAIL_DMARC_CONFIG_FILE} = $ini;
    lives_ok { Mail::DMARC::Report::Sender->new->run }
        'smartssl is not consulted when it will never be used';
    unlink $ini;
};

subtest 'an unusable smartssl stops the run before any report is touched' => sub {
    my ( $fh, $ini ) = tempfile( SUFFIX => '.ini' );
    print {$fh} <<"EO_INI";
[organization]
domain   = dmarc-test.example.net
org_name = Test
email    = dmarc\@example.com

[report_store]
backend = SQL
dsn     = dbi:SQLite:dbname=t/reports-test.sqlite

[smtp]
hostname  = mail.example.com
smarthost = relay.example.com
smartssl  = tls
EO_INI
    close $fh;

    local $ENV{MAIL_DMARC_CONFIG_FILE} = $ini;
    throws_ok { Mail::DMARC::Report::Sender->new->run }
        qr/unknown smtp.smartssl/,
        'a typo is refused at startup, not once per report';
    unlink $ini;
};

done_testing();
