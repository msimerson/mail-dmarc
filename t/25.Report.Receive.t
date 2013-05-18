use strict;
use warnings;

use Data::Dumper;
use Test::More;

use IO::Compress::Gzip;
use IO::Compress::Zip;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Receive';
use_ok( $mod );
my $recv = $mod->new;
isa_ok( $recv, $mod );

test_from_email_msg();
test_get_submitter_from_subject();

done_testing();
exit;

sub test_get_submitter_from_subject {
    my %subjects = (
        'aol.com'     => 'Subject: Report Domain:theartfarm.com Submitter:aol.com
 Report-ID:theartfarm.com_1366084800',
        'ivenue.com'  => 'Subject: Report Domain: tnpi.net Submitter: Ivenue.com Report-ID: tnpi.net-1366977854@Ivenue.com',
        'hotmail.com' => 'Subject: =?utf-8?B?UmVwb3J0IERvbWFpbjogc2ltZXJzb24ubmV0IFN1Ym1pdHRlcjogaG90bWFpbC5jb20gUmVwb3J0LUlEOiA8YTY2YWVmZWIzZjI3NGNhYmJmZGM2MWMwMTVlNTg2N2VAaG90bWFpbC5jb20+?=',
        'google.com'  => 'Subject: Report domain: timbersmart.com Submitter: google.com Report-ID: 6022178961730607282',
        'hotmail.com' => 'Subject: =?utf-8?B?UmVwb3J0IERvbWFpbjogbHluYm95ZXIuY29tIFN1Ym1pdHRlcjogaG90bWFpbC5jb20gUmVwb3J0LUlEOiA8MDJjNTM5YWY0ZjE2NGFlZGE3ZGQxZTdhYWJhOTc1MWJAaG90bWFpbC5jb20+?=',
        'yahoo.com'   => 'Subject: Report Domain: timbersmart.com Submitter: yahoo.com Report-ID: <1368868092.438744>',
            );

    foreach my $dom ( keys %subjects ) {
        my $subject = $subjects{$dom};
        cmp_ok( $recv->get_submitter_from_subject( \$subject ), 'eq', $dom, "get_submitter_from_subject, $dom");
    };
};

sub test_from_email_msg {
    if ( -f 'report.msg' ) {
        ok( $recv->from_email_msg('report.msg'), 'from_email_msg');
    };
};
