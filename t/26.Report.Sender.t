use strict;
use warnings;

use Test::More;
use Test::Exception;
use File::Temp ();
use Net::DNS::Resolver::Mock;

$ENV{MAIL_DMARC_CONFIG_FILE} = 't/mail-dmarc.ini';

use lib 'lib';
use Mail::DMARC::PurePerl;
use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use Mail::DMARC::Test::Transport;
use Email::Sender::Transport::Failable;
use Email::Sender::Transport::Test;
use Email::Sender::Success;

my $resolver = new Net::DNS::Resolver::Mock();
$resolver->zonefile_parse(join("\n",
'fastmaildmarc.com.        600 MX  10 in1-smtp.messagingengine.com.',
'_dmarc.fastmaildmarc.com. 600 TXT "v=DMARC1; p=reject; rua=mailto:rua@fastmaildmarc.com"',
''));

# We test both method and object type callbacks
foreach my $callback_type ( qw{ method object fail fallback } ) {

    subtest $callback_type => sub{
        unlink 't/reports-test.sqlite' if -e 't/reports-test.sqlite'; # Clear test database for each run

        my $dmarc = Mail::DMARC::PurePerl->new;
        $dmarc->set_resolver($resolver);

        $dmarc->set_fake_time( time-86400);
        $dmarc->init();
        $dmarc->source_ip('66.128.51.165');
        $dmarc->envelope_to('fastmaildmarc.com');
        $dmarc->envelope_from('fastmaildmarc.com');
        $dmarc->header_from('fastmaildmarc.com');
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
        my $result = $dmarc->validate($policy);
        $dmarc->save_aggregate;
        $dmarc->set_fake_time( time+86400);
        use Mail::DMARC::Report::Sender;
        my $sender = Mail::DMARC::Report::Sender->new;
        my @deliveries;

        if ( $callback_type eq 'method' ) {
            my $transport = Email::Sender::Transport::Test->new;
            $sender->set_transports_method( sub{
                my @transports;
                push @transports, $transport;
                return @transports;
            });
            $sender->run;
            @deliveries = $transport->deliveries;
        }
        elsif ( $callback_type eq 'object' ) {
            my $transports = Mail::DMARC::Test::Transport->new;
            $sender->set_transports_object( $transports );
            $sender->run;
            @deliveries = $transports->get_test_transport->deliveries;
        }
        elsif ( $callback_type eq 'fail' ) {
            my $transport = Email::Sender::Transport::Test->new;
            my $transport_fail = Email::Sender::Transport::Failable->new(
                transport => $transport,
                failure_conditions => [ sub{ return 1 } ],
            );
            $sender->set_transports_method( sub{
                my @transports;
                push @transports, $transport_fail;
                return @transports;
            });
            $sender->run;
            @deliveries = $transport_fail->transport->deliveries;
        }
        elsif ( $callback_type eq 'fallback' ) {
            my $transport = Email::Sender::Transport::Test->new;
            my $transport_fail = Email::Sender::Transport::Failable->new(
              transport => $transport,
              failure_conditions => [ sub{ return 1 } ],
            );
            $sender->set_transports_method( sub{
                my @transports;
                push @transports, $transport_fail;
                push @transports, $transport;
                return @transports;
            });
            $sender->run;
            @deliveries = $transport->deliveries;
        }
        else {
            die 'Unknown callback type in test';
        }

        if ( $callback_type eq 'fail' ) {
            is( @deliveries, 0, 'Email send fails' );
        }
        else {
            is( @deliveries, 1, '1 Email sent' );
            is( $deliveries[0]->{envelope}->{to}->[0], 'rua@fastmaildmarc.com', 'Sent to correct address' );
            my $body = ${$deliveries[0]->{email}->[0]->{body}};
            is( $body =~ /This is a DMARC aggregate report for fastmaildmarc.com/, 1, 'Human readable description' );
            is( $body =~ /1 records.\n0 passed.\n1 failed./, 1, 'Human readable summary');
            is( $body =~ /Content-Type: application\/gzip/, 1, 'Gzip attachment' );
        }
    };

}

# ->code on a plain string exception threw past the code that retires reports.
{
    package Mail::DMARC::Test::Transport::PlainDie;
    use Moo;
    with 'Email::Sender::Transport';
    sub send_email {
        die "SMTP connect failed: 530 5.7.0 Authentication required\n";
    }
}

{
    package Mail::DMARC::Test::Transport::Permanent;
    use Moo;
    with 'Email::Sender::Transport';
    sub send_email {
        Email::Sender::Failure->throw(
            { message => 'no such mailbox', code => 550 } );
    }
}

sub queue_one_report {
    unlink 't/reports-test.sqlite' if -e 't/reports-test.sqlite';

    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    $dmarc->set_fake_time( time - 86400 );
    $dmarc->init();
    $dmarc->source_ip('66.128.51.165');
    $dmarc->envelope_to('fastmaildmarc.com');
    $dmarc->envelope_from('fastmaildmarc.com');
    $dmarc->header_from('fastmaildmarc.com');
    $dmarc->dkim( [ { domain => 'tnpi.net', selector => 'jan2015',
                result => 'fail', human_result => 'fail (body has been altered)' } ] );
    $dmarc->spf( [ { domain => 'tnpi.net', scope => 'mfrom', result => 'pass' } ] );

    my $policy = $dmarc->discover_policy;
    $dmarc->validate($policy);
    $dmarc->save_aggregate;
    $dmarc->set_fake_time( time + 86400 );
    return;
}

sub reports_queued {
    return scalar @{ Mail::DMARC::Report->new->store->backend->get_report->{data} };
}

sub smarthost_ini {
    my ( $fh, $ini ) = File::Temp::tempfile( SUFFIX => '.ini' );
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
EO_INI
    close $fh;
    return $ini;
}

subtest 'a 5xx on one rung does not stop the ladder' => sub {
    queue_one_report();

    my $rejected = Mail::DMARC::Test::Transport::Permanent->new;
    my $working  = Email::Sender::Transport::Test->new;

    my $ini = smarthost_ini();
    local $ENV{MAIL_DMARC_CONFIG_FILE} = $ini;

    my $sender = Mail::DMARC::Report::Sender->new;
    $sender->{smarthost} = [ $rejected, $working ];
    $sender->run;

    # A relay refusing on 25 is exactly what the later rung is for.
    is( scalar $working->deliveries, 1, 'the next rung is still tried' );
    cmp_ok( reports_queued(), '==', 0, 'and the report is retired' );
    unlink $ini;
};

subtest 'a 5xx still falls back where the routes are different hosts' => sub {
    queue_one_report();

    my $rejected = Mail::DMARC::Test::Transport::Permanent->new;
    my $working  = Email::Sender::Transport::Test->new;

    my $sender = Mail::DMARC::Report::Sender->new;
    $sender->set_transports_method( sub { return ( $rejected, $working ) } );
    $sender->run;

    is( scalar $working->deliveries, 1,
        'a custom transports list keeps its fallback' );
};

subtest 'a send failure that is not a Failure object still retires the report'
    => sub {
    unlink 't/reports-test.sqlite' if -e 't/reports-test.sqlite';

    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    $dmarc->set_fake_time( time - 86400 );
    $dmarc->init();
    $dmarc->source_ip('66.128.51.165');
    $dmarc->envelope_to('fastmaildmarc.com');
    $dmarc->envelope_from('fastmaildmarc.com');
    $dmarc->header_from('fastmaildmarc.com');
    $dmarc->dkim( [ { domain => 'tnpi.net', selector => 'jan2015',
                result => 'fail', human_result => 'fail (body has been altered)' } ] );
    $dmarc->spf( [ { domain => 'tnpi.net', scope => 'mfrom', result => 'pass' } ] );

    my $policy = $dmarc->discover_policy;
    $dmarc->validate($policy);
    $dmarc->save_aggregate;
    $dmarc->set_fake_time( time + 86400 );

    my $store = Mail::DMARC::Report->new->store;
    cmp_ok( scalar @{ $store->backend->get_report->{data} }, '==', 1,
        'one report is queued' );

    my $sender = Mail::DMARC::Report::Sender->new;
    my $transport = Mail::DMARC::Test::Transport::PlainDie->new;
    $sender->set_transports_method( sub { return ($transport) } );

    lives_ok { $sender->run } 'the run completes';

    cmp_ok( scalar @{ $store->backend->get_report->{data} }, '==', 0,
        'the failed report is retired rather than left to fail forever' );
};

{
    package Mail::DMARC::Test::Transport::Answered;
    use Moo;
    with 'Email::Sender::Transport';
    has ssl => ( is => 'ro' );
    sub send_email {
        Email::Sender::Failure->throw(
            { message => 'greylisted, try again', code => 451 } );
    }
}

{
    package Mail::DMARC::Test::Transport::Clear;
    use Moo;
    with 'Email::Sender::Transport';
    has ssl  => ( is => 'ro', default => 0 );
    has sent => ( is => 'rw', default => 0 );
    sub send_email {
        my ($self) = @_;
        $self->sent( $self->sent + 1 );
        return Email::Sender::Success->new;
    }
}

{
    package Mail::DMARC::Test::Transport::Timeout;
    use Moo;
    with 'Email::Sender::Transport';
    has ssl => ( is => 'ro' );
    sub send_email { die "timeout\n" }
}

subtest 'a host that answered is not retried without encryption' => sub {
    queue_one_report();

    my $answered = Mail::DMARC::Test::Transport::Answered->new(
        ssl => 'maybestarttls' );
    my $cleartext = Mail::DMARC::Test::Transport::Clear->new;

    my $sender = Mail::DMARC::Report::Sender->new;
    $sender->set_transports_method( sub { return ( $answered, $cleartext ) } );
    $sender->run;

    # 451 came from a completed session, so repeating it in the clear would
    # put the report on the wire for a greylisting.
    cmp_ok( $cleartext->sent, '==', 0, 'the cleartext rung is skipped' );
};

subtest 'a timeout keeps the errors from earlier routes' => sub {
    queue_one_report();

    my $refused = Mail::DMARC::Test::Transport::Answered->new(
        ssl => 'starttls' );
    my $timed_out = Mail::DMARC::Test::Transport::Timeout->new(
        ssl => 'starttls' );

    my $sender = Mail::DMARC::Report::Sender->new;
    $sender->{verbose} = 1;
    $sender->set_transports_method( sub { return ( $refused, $timed_out ) } );

    my $output = '';
    {
        local *STDOUT;
        open STDOUT, '>', \$output or die "cannot capture STDOUT: $!";
        $sender->run;
    }

    # log_output encodes commas, so the joined message arrives as
    # "greylisted#044 try again#044 timeout"
    like( $output, qr/greylisted/,
        'the earlier route is still reported' );
    like( $output, qr/timeout/, 'along with the timeout that stopped it' );
    like( $output, qr/send_error_code=451\S*\s*error/,
        'and both codes are kept in order' );
};

subtest 'the report alarm stops the ladder rather than advancing it' => sub {
    queue_one_report();

    my $timed_out = Mail::DMARC::Test::Transport::Timeout->new(
        ssl => 'maybestarttls' );
    my $next = Email::Sender::Transport::Test->new;

    my $sender = Mail::DMARC::Report::Sender->new;
    $sender->set_transports_method( sub { return ( $timed_out, $next ) } );
    $sender->run;

    # the alarm bounds the report, is not rearmed, and the message may already
    # have been accepted
    is( scalar $next->deliveries, 0, 'no further rung is tried' );
};

# Direct to MX has the same exposure as a smart host: a receiver whose
# certificate cannot be verified fails the handshake closed, and its reports
# would be dropped rather than delivered.
subtest 'every MX is tried encrypted before any is tried in the clear' => sub {
    my $dmarc = Mail::DMARC::PurePerl->new;
    $dmarc->set_resolver($resolver);
    my $report = $dmarc->report;
    $report->config->{smtp}{smarthost} = '';

    my @t = Mail::DMARC::Report::Sender->new->get_transports_for(
        {   report   => $report,
            to       => 'rua@fastmaildmarc.com',
            log_data => {},
        }
    );

    cmp_ok( scalar @t, '>=', 2, 'more than one route' );
    is( $t[0]->ssl, 'maybestarttls', 'encrypted first' );
    ok( !$t[-1]->ssl, 'cleartext last' );

    my @encrypted = grep { $_->ssl } @t;
    my @clear     = grep { !$_->ssl } @t;
    ok( @encrypted && @clear, 'both passes present' );

    my @first = $t[0]->hosts;
    ok( scalar @first, 'the MX list reaches the transport' );
    is_deeply( [ $t[-1]->hosts ], \@first,
        'and the cleartext pass covers the same hosts' );
};

done_testing;

