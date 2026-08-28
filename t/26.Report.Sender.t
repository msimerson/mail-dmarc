use strict;
use warnings;

use Test::More;
use Test::Exception;
use Net::DNS::Resolver::Mock;

$ENV{MAIL_DMARC_CONFIG_FILE} = 't/mail-dmarc.ini';

use lib 'lib';
use Mail::DMARC::PurePerl;
use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use Mail::DMARC::Test::Transport;
use Email::Sender::Transport::Failable;
use Email::Sender::Transport::Test;

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

subtest 'a permanent rejection is not retried on the next route' => sub {
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

    my $rejected = Mail::DMARC::Test::Transport::Permanent->new;
    my $working  = Email::Sender::Transport::Test->new;

    my $sender = Mail::DMARC::Report::Sender->new;
    $sender->set_transports_method( sub { return ( $rejected, $working ) } );
    $sender->run;

    is( scalar $working->deliveries, 0,
        'the later route is not tried after a 5xx' );

    my $store = Mail::DMARC::Report->new->store;
    cmp_ok( scalar @{ $store->backend->get_report->{data} }, '==', 0,
        'and the report is retired straight away' );
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

done_testing;

