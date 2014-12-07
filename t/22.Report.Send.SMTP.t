use strict;
use warnings;

use Data::Dumper;
use Test::More;

use IO::Compress::Gzip;

use lib 'lib';
use Mail::DMARC::Policy;
use Mail::DMARC::Report::Aggregate;

my $mod = 'Mail::DMARC::Report::Send::SMTP';
use_ok($mod);
my $smtp = $mod->new;
isa_ok( $smtp, $mod );

open my $REP, '<', 'share/dmarc-report-2013-draft.xsd'
    or die "unable to open: $!";
my $report = join( '', <$REP> );
close $REP;
my $zipped;
IO::Compress::Gzip::gzip( \$report, \$zipped ) or die "unable to compress";

my $agg = Mail::DMARC::Report::Aggregate->new;
my $pol = Mail::DMARC::Policy->new;
$pol->domain('they.com');
$agg->policy_published( $pol );
$agg->metadata->begin( time - 10000 );
$agg->metadata->end( time - 100 );
$agg->metadata->report_id( '2013.06.01.6789' );

test_get_subject();
test_get_domain_mx();
test_get_smtp_hosts();
test_human_summary();
test_get_filename();
test_get_timestamp_rfc2822();
test_get_helo_hostname();
test_assemble_message();

done_testing();
exit;

sub test_get_subject {
    my $subject = $smtp->get_subject( \$agg );
    ok( $subject, "get_subject, $subject" );
};

sub test_get_helo_hostname {
    my $helo = $smtp->get_helo_hostname();
    ok( $helo, "get_helo_hostname, $helo" );
};

sub test_get_timestamp_rfc2822 {
    my $r = $smtp->get_timestamp_rfc2822();
    ok( $r, "get_timestamp_rfc2822, $r");
};

sub test_get_domain_mx {
    my %tests = (
        'tnpi.net' => [ { 'pref' => 10, 'addr' => 'mail.theartfarm.com' } ],
    );

    foreach my $dom ( keys %tests ) {
        my $r = $smtp->get_domain_mx( $dom );
        if (!$r) {
            print "ERROR: it appears your DNS is not working.\n";
            next;
        }

        ok( $r, "get_domain_mx, $dom");
        is_deeply( $r, $tests{$dom}, "get_domain_mx, $dom, deeply");
#       print Dumper($r);
    };
};

sub test_human_summary {
    $agg->record( {
            auth_results => { spf => [ { } ], },
            identifiers => {
                header_from => 'they.com',
            },
            row => {
                source_ip => '192.2.0.1',
                policy_evaluated => {
                    disposition=>'none',
                    dkim => 'pass',
                    spf => 'fail'
            } },
        });
    $agg->record( {
            auth_results => { spf => [ { } ], },
            identifiers => {
                header_from => 'they.com',
            },
            row => {
                source_ip => '192.2.0.1',
                policy_evaluated => {
                        disposition=>'none',
                        dkim => 'fail',
                        spf => 'pass'
                },
            },
        } );
    $agg->record( {
            auth_results => { spf => [ { } ], },
            identifiers => {
                header_from => 'they.com',
            },
            row => {
                source_ip => '192.2.0.1',
                policy_evaluated => {
                    disposition => 'none',
                    dkim => 'fail',
                    spf => 'fail'
                }
            }
        } );
    my $sum = $smtp->human_summary( \$agg );
    ok( $sum, 'human_summary' );
#   print $sum;
}

sub test_get_filename {
    my $name = $smtp->get_filename(\$agg);
    ok( $name, "get_filename, $name");
};

sub test_assemble_message {
    my $mess = $smtp->assemble_message( \$agg, 'matt@example.com', $zipped );
    ok( $mess, "assemble_message" );
    #warn print $mess;
}

sub test_get_smtp_hosts {
    my $initial_smarthost = $smtp->config->{smtp}{smarthost};
    $smtp->config->{smtp}{smarthost} = 'foo.example.com';
    my @mx = $smtp->get_smtp_hosts('bar.com');
    is_deeply( \@mx, ['foo.example.com'], "get_smtp_hosts, smarthost");

    $smtp->config->{smtp}{smarthost} = undef;
    my $tnpi_expected = [ 'mail.theartfarm.com', 'tnpi.net' ];
    my @hosts = $smtp->get_smtp_hosts('tnpi.net');
    is_deeply( \@hosts, $tnpi_expected, "get_smtp_hosts, tnpi.net");
#   print Dumper(\@hosts);

    $smtp->config->{smtp}{smarthost} = $initial_smarthost;
}

