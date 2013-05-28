use strict;
use warnings;

use Data::Dumper;
use Test::More;

use IO::Compress::Gzip;
use IO::Compress::Zip;
use IO::Uncompress::Unzip qw($UnzipError);
use IO::Uncompress::Gunzip qw($GunzipError);

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Send';
use_ok($mod);
my $send = $mod->new;
isa_ok( $send,       $mod );
isa_ok( $send->smtp, 'Mail::DMARC::Report::Send::SMTP' );
isa_ok( $send->http, 'Mail::DMARC::Report::Send::HTTP' );
isa_ok( $send->uri,  'Mail::DMARC::Report::URI' );

test_compress_report();
test_human_summary();

done_testing();
exit;

sub test_human_summary {
    my $report = {
        record => [
            { disposition=>'none',dkim => 'pass', spf => 'fail' },
            { disposition=>'none',dkim => 'fail', spf => 'pass' },
            { disposition=>'none',dkim => 'fail', spf => 'fail' },
        ],
        policy_published => {
            domain => 'example.com',
        },
    };
    ok( $send->human_summary( \$report ), 'human_summary' );
}

sub test_compress_report {

    # has to be moderately large to overcome zip format overhead
    my $xml        = '<xml></xml>' x 200;
    my $compressed = $send->compress_report( \$xml );
    ok( length $xml > length $compressed, 'compress_report' );

    my $decompressed;
    IO::Uncompress::Unzip::unzip( \$compressed => \$decompressed )
        or die "unzip failed: $UnzipError\n";
    cmp_ok( $decompressed, 'eq', $xml, "compress_report, extracts" );
}
