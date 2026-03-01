use strict;
use warnings;

use Data::Dumper;
use Test::More;

use IO::Compress::Gzip;
use IO::Compress::Zip;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Receive';
use_ok($mod);
my $recv = $mod->new;
isa_ok( $recv, $mod );

$recv->config('t/mail-dmarc.ini');

test_from_email_file();
test_from_file_xml();
test_from_file_gzip();
test_from_file_zip();
test_from_file_errors();
test_get_submitter_from_filename();
test_get_submitter_from_subject();
test_from_imap();

done_testing();
exit;

sub test_from_imap {
    my $skip_reason = '';

    eval "require Net::IMAP::Simple";
    $skip_reason .= "Net::IMAP::Simple not installed" if $@;

    my $c = $recv->config->{imap};
    if ( !$c->{server} || !$c->{user} || !$c->{pass} ) {
        $skip_reason .= " and \n" if $skip_reason;
        $skip_reason .= "imap not configured in mail-dmarc.ini";
    }

SKIP: {
        skip $skip_reason, 1 if $skip_reason;
        ok( $recv->from_imap(), "from_imap" );
    }
}

sub test_get_submitter_from_subject {
    my %subjects = (
        'aol.com' => 'Subject: Report Domain:theartfarm.com Submitter:aol.com
 Report-ID:theartfarm.com_1366084800',
        'ivenue.com' =>
            'Subject: Report Domain: tnpi.net Submitter: Ivenue.com Report-ID: tnpi.net-1366977854@Ivenue.com',
        'hotmail.com' =>
            'Subject: =?utf-8?B?UmVwb3J0IERvbWFpbjogc2ltZXJzb24ubmV0IFN1Ym1pdHRlcjogaG90bWFpbC5jb20gUmVwb3J0LUlEOiA8YTY2YWVmZWIzZjI3NGNhYmJmZGM2MWMwMTVlNTg2N2VAaG90bWFpbC5jb20+?=',
        'google.com' =>
            'Subject: Report domain: timbersmart.com Submitter: google.com Report-ID: 6022178961730607282',
        'hotmail.com' =>
            'Subject: =?utf-8?B?UmVwb3J0IERvbWFpbjogbHluYm95ZXIuY29tIFN1Ym1pdHRlcjogaG90bWFpbC5jb20gUmVwb3J0LUlEOiA8MDJjNTM5YWY0ZjE2NGFlZGE3ZGQxZTdhYWJhOTc1MWJAaG90bWFpbC5jb20+?=',
        'yahoo.com' =>
            'Subject: Report Domain: timbersmart.com Submitter: yahoo.com Report-ID: <1368868092.438744>',
    );

    foreach my $dom ( keys %subjects ) {
        my $subject = $subjects{$dom};
        cmp_ok( $recv->get_submitter_from_subject($subject),
            'eq', $dom, "get_submitter_from_subject, $dom" );
    }

    # Test UUID handling
    $recv->report->init();
    my $meta = $recv->report->aggregate->metadata;
    $recv->get_submitter_from_subject(
        'Subject: Report Domain: example.com Submitter: sender.example Report-ID: <uuid-test>'
    );
    is( $meta->uuid, 'uuid-test', 'subject parser sets metadata uuid' );
}

sub test_get_submitter_from_filename {
    $recv->{_envelope_to} = undef;
    $recv->{_header_from} = undef;

    my $result = $recv->get_submitter_from_filename('submit.example!report.example!1!2');
    is( $result, 'submit.example', 'filename parser extracts envelope submitter' );
    is( $recv->{_header_from}, 'report.example', 'filename parser sets header from domain' );

    # Test early return when submitter already set
    $recv->{_envelope_to} = 'existing.submitter';
    my $should_be_undef = $recv->get_submitter_from_filename('new.submitter!new.header!1!2');
    ok( !defined($should_be_undef), 'filename parser returns early when submitter already set' );
    is( $recv->{_envelope_to}, 'existing.submitter', 'existing submitter is preserved' );
}

sub test_from_file_errors {
    eval { $recv->from_file() };
    like( $@, qr/missing message/i, 'from_file croaks when file argument is missing' );

    eval { $recv->from_file('t/fixtures/not-there.xml') };
    like( $@, qr/no such file/i, 'from_file croaks for missing file path' );
}

sub test_from_file_xml {
    my $file = 't/fixtures/test_dmarc.xml';
    return if !-f $file;

    eval "require DBD::SQLite";
    if ($@) {
        SKIP: { skip 'DBD::SQLite not available', 1 }
        return;
    }

    my $result = eval { $recv->from_file($file) };
    if ($@) {
        diag "from_file XML failed: $@";
        ok(0, "from_file with XML file");
    } else {
        cmp_ok( $result, 'eq', 'aggregate', "from_file with XML file" );
    }
}

sub test_from_file_gzip {
    my $file = 't/fixtures/test_dmarc.xml.gz';
    return if !-f $file;

    eval "require DBD::SQLite";
    if ($@) {
        SKIP: { skip 'DBD::SQLite not available', 1 }
        return;
    }

    my $result = eval { $recv->from_file($file) };
    if ($@) {
        diag "from_file gzip failed: $@";
        ok(0, "from_file with gzip file");
    } else {
        cmp_ok( $result, 'eq', 'aggregate', "from_file with gzip file" );
    }
}

sub test_from_file_zip {
    my $file = 't/fixtures/test_dmarc.xml.zip';
    return if !-f $file;

    eval "require DBD::SQLite";
    if ($@) {
        SKIP: { skip 'DBD::SQLite not available', 1 }
        return;
    }

    my $result = eval { $recv->from_file($file) };
    if ($@) {
        diag "from_file zip failed: $@";
        ok(0, "from_file with zip file");
    } else {
        cmp_ok( $result, 'eq', 'aggregate', "from_file with zip file" );
    }
}

sub test_from_email_file {
    if ( -f 'report.msg' ) {
        $recv->verbose(1);
        ok( $recv->from_file('report.msg'), 'from_file' );
    }
}
