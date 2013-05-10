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

my $mod = 'Mail::DMARC::PurePerl';
use_ok( $mod );
my $dmarc = $mod->new;
isa_ok( $dmarc, $mod );

# this is equivalent to:
# Mail::DMARC::Report( dmarc => $dmarc );
my $report = $dmarc->report;
isa_ok( $report, 'Mail::DMARC::Report' );

isa_ok( $report->sendit,  'Mail::DMARC::Report::Send' );
isa_ok( $report->store,   'Mail::DMARC::Report::Store' );
isa_ok( $report->receive, 'Mail::DMARC::Report::Receive' );
isa_ok( $report->view,    'Mail::DMARC::Report::View' );

my $test_dom = 'tnpi.net';
#setup_dmarc_result() or die "failed setup\n";
#$dmarc->report->store() or diag Dumper( $dmarc->report );


#unlink $test_db_file;
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

