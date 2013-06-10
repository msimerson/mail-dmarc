use strict;
use warnings;

use Data::Dumper;
use Test::More;

use IO::Compress::Gzip;
use IO::Uncompress::Gunzip qw($GunzipError);
#use IO::Compress::Zip;    # legacy format
#use IO::Uncompress::Unzip qw($UnzipError);

use lib 'lib';

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

my $mod = 'Mail::DMARC::PurePerl';
use_ok($mod);
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

test_compress();

#setup_dmarc_result() or die "failed setup\n";
#$dmarc->report->store() or diag Dumper( $dmarc->report );

#unlink $test_db_file;
done_testing();
exit;

sub setup_dmarc_result {

    $dmarc->init();
    $dmarc->header_from($test_dom);
    $dmarc->source_ip('192.2.1.1');
    $dmarc->dkim(
        [ { domain => $test_dom, result => 'pass', selector => 'apr2013' } ]
    );
    $dmarc->spf(
        { domain => $test_dom, scope => 'mfrom', result => 'pass' } );
    $dmarc->validate() or diag Dumper($dmarc) and return;
    delete $dmarc->result->{published};
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
        },
        "result, pass, strict, $test_dom"
    ) or diag Dumper( $dmarc->result );
}

sub test_compress {

    # has to be moderately large to overcome zip format overhead
    my $xml        = '<xml></xml>' x 200;
    my $compressed = $report->compress( \$xml );
    ok( length $xml > length $compressed, 'compress_report' );

    my $decompressed;
    IO::Uncompress::Gunzip::gunzip( \$compressed => \$decompressed )
        or die "unzip failed: $GunzipError\n";
    cmp_ok( $decompressed, 'eq', $xml, "compress_report, extracts" );
}
