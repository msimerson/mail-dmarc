use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

eval "use DBD::SQLite 1.31";
if ( $@ ) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
};

use_ok( 'Mail::DMARC::PurePerl' );
my $dmarc = Mail::DMARC::PurePerl->new();
isa_ok( $dmarc, 'Mail::DMARC::PurePerl' );


isa_ok( $dmarc->report, 'Mail::DMARC::Report' );
isa_ok( $dmarc->report->store, 'Mail::DMARC::Report::Store');
ok( $dmarc->report->store->backend, "selected backend loaded" );

my $test_dom = 'tnpi.net';

# gotta have something to store. Populate a DMARC object
setup_dmarc_result() or die "failed setup\n";

#warn Dumper($dmarc->result->published);
#warn Dumper($dmarc->report->dmarc->header_from);
#warn Dumper($dmarc);
#done_testing(); exit;

# tell storage backend to use test settings
$dmarc->report->store->backend->config('t/mail-dmarc.ini');

# provide a fake reason
$dmarc->result->evaluated->reason->type('other');
$dmarc->result->evaluated->reason->comment('testing');

my $r = $dmarc->report->save;
ok( $r, "save results" );
print Dumper($r);

#unlink 't/reports-test.sqlite';  # test DB
done_testing();
exit;

sub setup_dmarc_result {

    $dmarc->init();
    $dmarc->header_from( $test_dom );
    $dmarc->source_ip( '192.2.1.1' );
    $dmarc->dkim([{ domain => $test_dom, result=>'pass', selector=> 'apr2013' }]);
    $dmarc->spf({ domain => $test_dom, scope=>'mfrom', result=>'pass' });
    $dmarc->validate() or diag Dumper($dmarc) and return;
    is_deeply( $dmarc->result->evaluated, {
        'result' => 'pass',
        'disposition' => 'none',
        'dkim_meta' => {
            'domain' => 'tnpi.net',
            'identity' => '',
            'selector' => 'apr2013',
        },
        'dkim' => 'pass',
        'spf' => 'pass',
        'dkim_align' => 'strict',
        'spf_align' => 'strict',
        },
        "evaluated, pass, strict, $test_dom")
        or diag Dumper($dmarc->result);
};

