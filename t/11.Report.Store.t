use strict;
use warnings;

use Data::Dumper;
use Net::DNS::Resolver::Mock;
use Test::More;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

my $resolver = new Net::DNS::Resolver::Mock();
$resolver->zonefile_parse(join("\n",
'tnpi.net.                         600 A   66.128.51.170',
'tnpi.net.                         600 MX  10 mail.theartfarm.com.',
'_dmarc.mail-dmarc.tnpi.net.       600 TXT "v=DMARC1; p=reject; rua=mailto:invalid@theartfarm.com; ruf=mailto:invalid@theartfarm.com; pct=90"',
'_dmarc.tnpi.net.                  600 TXT "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@theartfarm.com; ruf=mailto:dmarc-feedback@theartfarm.com; pct=100"',
'mail-dmarc.tnpi.net.              600 TXT "test zone for Mail::DMARC perl module"',
'mail-dmarc.tnpi.net._report._dmarc.theartfarm.com. 600 TXT "v=DMARC1; rua=mailto:invalid-test@theartfarm.com;"',
''));

use_ok('Mail::DMARC::PurePerl');
my $dmarc = Mail::DMARC::PurePerl->new();
$dmarc->set_resolver($resolver);
isa_ok( $dmarc, 'Mail::DMARC::PurePerl' );

isa_ok( $dmarc->report,        'Mail::DMARC::Report' );
isa_ok( $dmarc->report->store, 'Mail::DMARC::Report::Store' );
ok( $dmarc->report->store->backend, "selected backend loaded" );

my $test_dom = 'tnpi.net';

# gotta have something to store. Populate a DMARC object
setup_dmarc_result() or die "failed setup\n";

# tell storage backend to use test settings
$dmarc->report->store->backend->config('t/mail-dmarc.ini');

test_reason();

done_testing();
exit;

sub test_reason {
    ok( $dmarc->result->reason( type => 'other', comment => 'testing' ), "reason");
}

sub setup_dmarc_result {

    $dmarc->init();
    ok( $dmarc->header_from($test_dom),       "header_from" );
    ok( $dmarc->envelope_to('recipient.com'), 'envelope_to' );
    ok( $dmarc->source_ip('192.2.1.1'),       'source_ip' );
    $dmarc->dkim([ { domain => $test_dom, result => 'pass', selector => 'apr2013' } ]);
    $dmarc->spf({ domain => $test_dom, scope => 'mfrom', result => 'pass' } );
    $dmarc->validate() or diag Dumper($dmarc) and return;
    my $pub = delete $dmarc->result->{published};
    ok( $pub, "pub" );
    is_deeply(
        $dmarc->result,
        {   'result'      => 'pass',
            'disposition' => 'none',
            'dkim_meta'   => {
                'domain'   => 'tnpi.net',
                'identity' => '',
                'selector' => 'apr2013',
            },
            'dkim'       => 'pass',
            'spf'        => 'pass',
            'dkim_align' => 'strict',
            'spf_align'  => 'strict',
            'reason'     => [],
        },
        "result, pass, strict, $test_dom"
    ) or diag Dumper( $dmarc->result );
    return $dmarc->result->published($pub);
}

