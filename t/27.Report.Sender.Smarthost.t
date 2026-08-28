use strict;
use warnings;

use Test::More;
use Test::Exception;
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

# A transport whose route we can inspect without connecting anywhere.
sub transports_for {
    my (%smtp) = @_;
    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    my $report = $dmarc->report;
    $report->config->{smtp}{$_} = $smtp{$_} foreach keys %smtp;
    my $sender = Mail::DMARC::Report::Sender->new;
    return $sender->get_transports_for( { report => $report } );
}

sub route {
    my ($transport) = @_;
    return sprintf '%s:%s/%s', $transport->host, $transport->port,
        ( $transport->ssl || 'none' );
}

subtest 'unconfigured smart host tries submission then the relay port' => sub {
    my @t = transports_for( smarthost => 'relay.example.com' );

    cmp_ok( scalar @t, '>=', 2, 'more than one route offered' );
    is( route( $t[0] ), 'relay.example.com:587/starttls',
        'submission with STARTTLS first' );
    cmp_ok( $t[1]->port, '==', 25, 'falls back to the relay port' );

    # A smart host that only listens on 25, or demands AUTH on 587, used to
    # leave every report queued rather than being retried here.
    ok( ( grep { $_->port == 25 } @t ), 'the relay port is among the routes' );
};

subtest 'an explicit port pins a single route' => sub {
    my @t = transports_for(
        smarthost => 'relay.example.com',
        smartport => 25,
    );
    cmp_ok( scalar @t, '==', 1, 'one route only' );
    is( route( $t[0] ), 'relay.example.com:25/starttls', 'the port asked for' );
};

subtest 'smartssl selects the TLS mode' => sub {
    my %expect = (
        'starttls'      => 'starttls',
        'maybestarttls' => 'maybestarttls',
        'ssl'           => 'ssl',
        'none'          => 'none',
        'NONE'          => 'none',
        '  starttls  '  => 'starttls',
    );
    foreach my $value ( sort keys %expect ) {
        my @t = transports_for(
            smarthost => 'relay.example.com',
            smartssl  => $value,
        );
        cmp_ok( scalar @t, '==', 1, "smartssl '$value' pins one route" );
        is( ( $t[0]->ssl || 'none' ), $expect{$value},
            "smartssl '$value' gives $expect{$value}" );
    }
};

subtest 'an unusable smartssl is refused, not guessed at' => sub {
    foreach my $value (qw/ tls yes secure starttls! 1 /) {
        throws_ok {
            transports_for(
                smarthost => 'relay.example.com',
                smartssl  => $value,
            );
        }
        qr/unknown smtp.smartssl/, "smartssl '$value' croaks";
    }
};

subtest 'credentials pin the route rather than being retried in the clear' => sub {
    my @t = transports_for(
        smarthost => 'relay.example.com',
        smartuser => 'reporter',
        smartpass => 'secret',
    );
    cmp_ok( scalar @t, '==', 1, 'one route only' );
    cmp_ok( $t[0]->port, '==', 587, 'submission' );
    is( $t[0]->ssl, 'starttls', 'still encrypted' );
    is( $t[0]->sasl_username, 'reporter', 'username passed through' );
};

subtest 'an empty setting is not a setting' => sub {
    my @t = transports_for(
        smarthost => 'relay.example.com',
        smartport => '',
        smartssl  => '',
        smartuser => '',
        smartpass => '',
    );
    cmp_ok( scalar @t, '>=', 2, 'still falls back' );
    is( route( $t[0] ), 'relay.example.com:587/starttls', 'submission first' );
};

subtest 'a transport supplied to the constructor still wins' => sub {
    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    my $report = $dmarc->report;
    $report->config->{smtp}{smarthost} = 'relay.example.com';

    my $canned = Email::Sender::Transport::SMTP::Persistent->new(
        { host => 'given.example.com', port => 2525 } );
    my $sender = Mail::DMARC::Report::Sender->new( { smarthost => $canned } );

    my @t = $sender->get_transports_for( { report => $report } );
    cmp_ok( scalar @t, '==', 1, 'the given transport is used' );
    is( $t[0]->host, 'given.example.com', 'and nothing else is built' );
};

done_testing();
