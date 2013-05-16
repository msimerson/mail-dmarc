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

# tell storage backend to use test settings
$dmarc->report->store->backend->config('t/mail-dmarc.ini');

test_reason();
test_save();

done_testing();
exit;

sub test_save {
    my $r = $dmarc->report->save($dmarc);
    ok( $r, "save results" );
    print Dumper($r);
};

sub test_reason {
    $dmarc->result->reason->type('other');
    $dmarc->result->reason->comment('testing');
}

sub setup_dmarc_result {

    $dmarc->init();
    $dmarc->header_from( $test_dom );
    $dmarc->source_ip( '192.2.1.1' );
    $dmarc->dkim([{ domain => $test_dom, result=>'pass', selector=> 'apr2013' }]);
    $dmarc->spf({ domain => $test_dom, scope=>'mfrom', result=>'pass' });
    $dmarc->validate() or diag Dumper($dmarc) and return;
    my $pub = delete $dmarc->result->{published};
    is_deeply( $dmarc->result, {
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
        "result, pass, strict, $test_dom")
        or diag Dumper($dmarc->result);
    return $dmarc->result->published( $pub );
};

