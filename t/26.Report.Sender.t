#!/usr/bin/perl
# VERSION
use strict;
use warnings;

use Test::More;
use Mail::DMARC::PurePerl;

use Email::Sender::Transport::Test;

my $dmarc = Mail::DMARC::PurePerl->new;
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
my $transport = Email::Sender::Transport::Test->new;
$sender->set_transports_method( sub{
  my @transports;
  push @transports, $transport;
  return @transports;
});

$sender->run;

my @deliveries = $transport->deliveries;

is( scalar @deliveries, 1, '1 Email sent' );
is( $deliveries[0]->{envelope}->{to}->[0], 'rua@fastmaildmarc.com', 'Sent to correct address' );
my $body = ${$deliveries[0]->{email}->[0]->{body}};
is( $body =~ /This is a DMARC aggregate report for fastmaildmarc.com/, 1, 'Human readable description' );
is( $body =~ /1 records.\n0 passed.\n1 failed./, 1, 'Human readable summary');
is( $body =~ /Content-Type: application\/gzip/, 1, 'Gzip attachment' );
done_testing;

