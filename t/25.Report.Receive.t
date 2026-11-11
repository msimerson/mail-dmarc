use strict;
use warnings;

use Test::More;
use Test::Exception;

use Email::MIME;
use Email::Simple;
use File::Temp ();

# Receive builds its own Report, which reads the config from here rather than
# from the receiver; without it reports land in the bundled default store.
$ENV{MAIL_DMARC_CONFIG_FILE} = 't/mail-dmarc.ini';

use lib 'lib';
use Test::File::ShareDir -share => { -dist => { 'Mail-DMARC' => 'share' } };

my $mod = 'Mail::DMARC::Report::Receive';
use_ok($mod);
isa_ok( $mod->new, $mod );

my $DB = 't/reports-test.sqlite';

my %fixture = (
    xml => slurp('t/fixtures/test_dmarc.xml'),
    gz  => slurp('t/fixtures/test_dmarc.xml.gz'),
    zip => slurp('t/fixtures/test_dmarc.xml.zip'),
);

test_from_email_attachments();
test_from_email_submitter();
test_from_email_not_aggregate();
test_from_email_two_reports();
test_from_email_disposition_filename();
test_from_email_file();
test_from_file_xml();
test_from_file_gzip();
test_from_file_zip();
test_from_file_rfc9990_namespace();
test_from_file_errors();
test_from_mbox();
test_dmarc_receive_mbox();
test_get_submitter_from_filename();
test_get_submitter_from_subject();
test_from_imap();

unlink $DB;
done_testing();
exit;

sub slurp {
    my ($file) = @_;
    open my $fh, '<:raw', $file or die "open $file: $!";
    local $/;
    return <$fh>;
}

sub fresh_receiver {
    unlink $DB;
    return $mod->new;
}

sub stored_reports {
    my ($recv) = @_;
    my $backend = $recv->report->store->backend;
    return [ map { { %$_, rows => $backend->get_rr( rid => $_->{rid} )->{data} } }
            @{ $backend->retrieve } ];
}

sub report_email {
    my (%args) = @_;
    my @parts = (
        Email::MIME->create(
            attributes => {
                content_type => 'text/plain',
                charset      => 'utf-8',
                encoding     => '7bit',
            },
            body_str => "This is a DMARC aggregate report.\n",
        )
    );
    push @parts,
        Email::MIME->create(
        attributes => {
            content_type => $args{content_type},
            name         => $args{filename},
            filename     => $args{filename},
            disposition  => 'attachment',
            encoding     => 'base64',
        },
        body => $args{body},
        ) if $args{content_type};
    push @parts, @{ $args{parts} || [] };

    return Email::Simple->new(
        Email::MIME->create(
            header_str => [
                From    => 'noreply-dmarc@google.example',
                To      => 'dmarc@example.com',
                Subject => $args{subject}
                    // 'Report domain: example.com Submitter: google.example Report-ID: <subject-id>',
            ],
            parts => \@parts,
        )->as_string
    );
}

sub collect_warnings {
    my ($code) = @_;
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    my $result = $code->();
    return ( $result, join '', @warnings );
}

sub test_from_email_attachments {
    my $name = 'google.example!example.com!1609459200!1609545600';
    my @cases = (
        [ 'application/gzip',             "$name.xml.gz", $fixture{gz} ],
        [ 'application/zip',              "$name.zip",    $fixture{zip} ],
        [ 'application/x-zip-compressed', "$name.zip",    $fixture{zip} ],
        [ 'application/octet-stream',     "$name.xml.gz", $fixture{gz} ],

        # RFC 7489 7.2.1.1: uncompressed reports are sent as text/xml
        [ 'text/xml',        "$name.xml", $fixture{xml} ],
        [ 'application/xml', "$name.xml", $fixture{xml} ],
    );

    foreach my $case (@cases) {
        my ( $ct, $filename, $body ) = @$case;
        subtest "email with $ct attachment" => sub {
            my $recv = fresh_receiver();
            my $email = report_email(
                content_type => $ct,
                filename     => $filename,
                body         => $body,
            );
            my ( $type, $warned ) = collect_warnings(
                sub { $recv->from_email_simple($email) } );
            is( $type,   'aggregate', 'detected as an aggregate report' );
            is( $warned, '',          'without warnings' );

            my $reports = stored_reports($recv);
            is( scalar @$reports, 1, 'one report stored' ) or return;
            my $rep = $reports->[0];
            is( $rep->{uuid},        'subject-id',  'Report-ID from the Subject' );
            is( $rep->{author},      'Test Sender', 'org_name from the XML' );
            is( $rep->{from_domain}, 'example.com', 'policy domain from the XML' );
            is( scalar @{ $rep->{rows} },          1,          'one row stored' );
            is( $rep->{rows}[0]{source_ip},        '1.2.3.4',  'row source_ip' );
            is( $rep->{rows}[0]{envelope_to}, 'google.example', 'submitter from Subject' );
        };
    }
}

sub test_from_email_submitter {
    my $recv  = fresh_receiver();
    my $email = report_email(
        subject      => 'DMARC aggregate report',
        content_type => 'application/gzip',
        filename     => 'yahoo.example!example.com!1609459200!1609545600.xml.gz',
        body         => $fixture{gz},
    );
    is( $recv->from_email_simple($email), 'aggregate', 'report without a DMARC Subject' );
    my $rep = stored_reports($recv)->[0];
    is( $rep->{rows}[0]{envelope_to}, 'yahoo.example',
        'submitter falls back to the attachment filename' );
    is( $rep->{uuid}, '1234567890', 'Report-ID falls back to the XML report_id' );

    $recv  = fresh_receiver();
    $email = report_email(
        subject      => 'DMARC aggregate report',
        content_type => 'application/gzip',
        filename     => 'report.xml.gz',
        body         => $fixture{gz},
    );
    is( $recv->from_email_simple($email), 'aggregate', 'report with an unpatterned filename' );
    is( stored_reports($recv)->[0]{rows}[0]{envelope_to}, 'test.example',
        'submitter falls back to the reporter email domain' );

    my $second = xml_attachment( 'rx.example!example.com!1609459200!1609545600.xml',
        second_report_xml() );
    $recv  = fresh_receiver();
    $email = report_email(
        subject      => 'DMARC aggregate report',
        content_type => 'application/gzip',
        filename     => 'report.xml.gz',
        body         => $fixture{gz},
        parts        => [$second],
    );
    $recv->from_email_simple($email);
    my %envelope_to = map { $_->{uuid} => [ map { $_->{envelope_to} } @{ $_->{rows} } ] }
        @{ stored_reports($recv) };
    is_deeply( \%envelope_to, { 1234567890 => ['test.example'], second => ['rx.example'] },
        'the email domain fallback does not carry over to the next attachment' );
}

sub xml_attachment {
    my ( $filename, $xml, %name ) = @_;
    return Email::MIME->create(
        attributes => {
            content_type => 'text/xml',
            filename     => $filename,
            disposition  => 'attachment',
            encoding     => 'base64',
            %name,
        },
        body => $xml,
    );
}

sub second_report_xml {
    ( my $xml = $fixture{xml} ) =~ s{<report_id>1234567890</report_id>}{<report_id>second</report_id>}
        or die 'fixture report_id not found';
    $xml =~ s{<source_ip>1\.2\.3\.4</source_ip>}{<source_ip>5.6.7.8</source_ip>}
        or die 'fixture source_ip not found';
    return $xml;
}

sub test_from_email_two_reports {
    my $second_xml = second_report_xml();

    my $name  = 'rx.example!example.com!1609459200!1609545600.xml';
    my $recv  = fresh_receiver();
    my $email = report_email(
        parts => [
            xml_attachment( $name, $fixture{xml}, name => $name ),
            xml_attachment( $name, $second_xml,   name => $name ),
        ]
    );
    is( $recv->from_email_simple($email), 'aggregate', 'email with two reports' );

    my %by_uuid = map { $_->{uuid} => $_ } @{ stored_reports($recv) };
    is_deeply( [ sort keys %by_uuid ], [ 'second', 'subject-id' ],
        'the Subject Report-ID names the first report, the XML names the second' );
    is_deeply( [ map { $_->{source_ip} } @{ $by_uuid{'subject-id'}{rows} } ], ['1.2.3.4'],
        'the first report has only its own record' );
    is_deeply( [ map { $_->{source_ip} } @{ $by_uuid{second}{rows} } ], ['5.6.7.8'],
        'the second report has only its own record' );
    is( $by_uuid{second}{rows}[0]{envelope_to}, 'google.example',
        'the Subject submitter applies to every report' );
}

sub test_from_email_disposition_filename {
    my $recv  = fresh_receiver();
    my $name  = 'rx.example!example.com!1609459200!1609545600.xml.gz';
    my $email = report_email(
        subject => 'DMARC aggregate report',
        parts   => [
            Email::MIME->create(
                attributes => {
                    content_type => 'application/octet-stream',
                    filename     => $name,
                    disposition  => 'attachment',
                    encoding     => 'base64',
                },
                body => $fixture{gz},
            )
        ],
    );
    my ( $type, $warned ) = collect_warnings( sub { $recv->from_email_simple($email) } );
    is( $type,   'aggregate', 'attachment named only in Content-Disposition is a report' );
    is( $warned, '',          'without warnings' );
    is( stored_reports($recv)->[0]{rows}[0]{envelope_to},
        'rx.example', 'its Content-Disposition filename names the receiver' );
}

sub test_from_email_not_aggregate {
    my $recv = fresh_receiver();

    my ( $type, $warned )
        = collect_warnings( sub { $recv->from_email_simple( report_email() ) } );
    is( $type,   undef, 'text only email is not a report' );
    is( $warned, '',    'text parts are skipped quietly' );

    my $feedback = Email::MIME->create(
        attributes => { content_type => 'message/feedback-report', encoding => '7bit' },
        body       => "Feedback-Type: auth-failure\nVersion: 1\n",
    );
    ( $type, $warned ) = collect_warnings(
        sub { $recv->from_email_simple( report_email( parts => [$feedback] ) ) } );
    is( $type, 'forensic', 'message/feedback-report is a forensic report' );
    like( $warned, qr/forensic/, 'forensic reports are not processed yet' );

    ( $type, $warned ) = collect_warnings(
        sub {
            $recv->from_email_simple(
                report_email(
                    content_type => 'application/gzip',
                    filename     => 'x!example.com!1!2.xml.gz',
                    body         => 'this is not gzip',
                )
            );
        }
    );
    is( $type, undef, 'corrupt attachment is not reported as received' );
    like( $warned, qr/failure processing x!example\.com!1!2\.xml\.gz/,
        'corrupt attachment warns with its filename' );

    ( $type, $warned ) = collect_warnings(
        sub {
            $recv->from_email_simple(
                report_email(
                    content_type => 'image/png',
                    filename     => 'logo.png',
                    body         => "\x89PNG",
                )
            );
        }
    );
    is( $type, undef, 'unknown attachment is not a report' );
    like( $warned, qr{Unknown message part image/png}, 'unknown attachment warns' );

    is( scalar @{ stored_reports($recv) }, 0, 'nothing stored' );
}

sub test_from_email_file {
    my $recv = fresh_receiver();
    my $tmp  = File::Temp->new( SUFFIX => '.eml' );
    print {$tmp} report_email(
        content_type => 'application/gzip',
        filename     => 'google.example!example.com!1!2.xml.gz',
        body         => $fixture{gz},
    )->as_string;
    close $tmp;

    is( $recv->from_file("$tmp"), 'aggregate', 'from_file with a saved email' );
    is( scalar @{ stored_reports($recv) }, 1, 'its report is stored' );
}

sub test_from_file_xml {
    my $recv = fresh_receiver();
    is( $recv->from_file('t/fixtures/test_dmarc.xml'), 'aggregate', 'from_file with XML file' );
    my $row = stored_reports($recv)->[0]{rows}[0];
    is( $row->{source_ip},   '1.2.3.4',      'its row is stored' );
    is( $row->{envelope_to}, 'test.example', 'unpatterned filename, receiver from the reporter email' );

    $recv = fresh_receiver();
    my $dir  = File::Temp->newdir;
    my $file = "$dir/receiver.example!example.com!1609459200!1609545600.xml";
    open my $fh, '>:raw', $file or die "open $file: $!";
    print {$fh} $fixture{xml};
    close $fh;
    is( $recv->from_file($file), 'aggregate', 'from_file with an RFC named XML file' );
    is( stored_reports($recv)->[0]{rows}[0]{envelope_to},
        'receiver.example', 'RFC named file, receiver from the filename' );
}

sub test_from_file_gzip {
    my $recv = fresh_receiver();
    is( $recv->from_file('t/fixtures/test_dmarc.xml.gz'), 'aggregate', 'from_file with gzip file' );
    is( scalar @{ stored_reports($recv) }, 1, 'its report is stored' );
}

sub test_from_file_zip {
    my $recv = fresh_receiver();
    is( $recv->from_file('t/fixtures/test_dmarc.xml.zip'), 'aggregate', 'from_file with zip file' );
    is( scalar @{ stored_reports($recv) }, 1, 'its report is stored' );
}

sub test_from_file_rfc9990_namespace {
    my $recv = fresh_receiver();
    ( my $xml = $fixture{xml} )
        =~ s/<feedback>/<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">/;
    $xml =~ s/<report_metadata>/<version>1.0<\/version>\n  <report_metadata>/;

    my $tmp = File::Temp->new( SUFFIX => '.xml' );
    print {$tmp} $xml;
    close $tmp;

    is( $recv->from_file("$tmp"), 'aggregate', 'RFC 9990 namespaced report' );
    my $rep = stored_reports($recv)->[0];
    is( $rep->{uuid},                   '1234567890', 'its metadata is read' );
    is( $rep->{from_domain},            'example.com', 'its policy is read' );
    is( $rep->{rows}[0]{source_ip},     '1.2.3.4',     'its records are read' );
    is( $rep->{rows}[0]{disposition},   'none',        'its disposition is read' );
}

sub test_from_file_errors {
    my $recv = fresh_receiver();
    throws_ok { $recv->from_file() } qr/missing message/i,
        'from_file croaks when file argument is missing';

    throws_ok { $recv->from_file('t/fixtures/not-there.xml') } qr/no such file/i,
        'from_file croaks for missing file path';
}

sub mbox_file {
    my $tmp = File::Temp->new( SUFFIX => '.mbox' );
    foreach my $id (qw/ mbox-one mbox-two /) {
        my $email = report_email(
            subject => "Report domain: example.com Submitter: google.example Report-ID: <$id>",
            content_type => 'application/gzip',
            filename     => 'google.example!example.com!1!2.xml.gz',
            body         => $fixture{gz},
        )->as_string;

        # mboxrd quoting of a body line that would otherwise start a message
        $email =~ s/^This is a DMARC/>From the desk of DMARC/m;
        print {$tmp} "From noreply-dmarc\@google.example Thu Jan  1 00:00:00 2021\n";
        print {$tmp} "$email\n";
    }
    close $tmp;
    return $tmp;
}

sub test_from_mbox {
    my $recv = fresh_receiver();
    throws_ok { $recv->from_mbox() } qr/missing mbox file/, 'from_mbox requires a file';
    throws_ok { $recv->from_mbox('t/fixtures/not-there.mbox') } qr/unable to read/,
        'from_mbox croaks for a missing file';

    my $mbox = mbox_file();
    is( $recv->from_mbox("$mbox"), 2, 'from_mbox reads every message' );
    is_deeply( [ sort map { $_->{uuid} } @{ stored_reports($recv) } ],
        [qw/ mbox-one mbox-two /], 'and stores each report' );
}

sub test_dmarc_receive_mbox {
    my $recv = fresh_receiver();
    my $mbox = mbox_file();
    my $run  = q{use Test::File::ShareDir -share => { -dist => { 'Mail-DMARC' => 'share' } };}
        . q{ do './bin/dmarc_receive'; die $@ if $@;};
    open my $ph, '-|', $^X, '-Ilib', '-e', $run, '--', '--mbox', "$mbox"
        or die "run dmarc_receive: $!";
    my $out = do { local $/; <$ph> };
    close $ph;
    is( $?, 0, 'dmarc_receive --mbox <file> runs' ) or diag $out;
    is( scalar @{ stored_reports($recv) }, 2, 'and stores the reports in the mbox' );
}

sub test_from_imap {
    my $recv        = fresh_receiver();
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
    my $recv     = fresh_receiver();
    my %subjects = (
        'aol.com' => 'Subject: Report Domain:theartfarm.com Submitter:aol.com
 Report-ID:theartfarm.com_1366084800',
        'ivenue.com' =>
            'Subject: Report Domain: tnpi.net Submitter: Ivenue.com Report-ID: tnpi.net-1366977854@Ivenue.com',
        'hotmail.com' =>
            'Subject: =?utf-8?B?UmVwb3J0IERvbWFpbjogc2ltZXJzb24ubmV0IFN1Ym1pdHRlcjogaG90bWFpbC5jb20gUmVwb3J0LUlEOiA8YTY2YWVmZWIzZjI3NGNhYmJmZGM2MWMwMTVlNTg2N2VAaG90bWFpbC5jb20+?=',
        'google.com' =>
            'Subject: Report domain: timbersmart.com Submitter: google.com Report-ID: 6022178961730607282',
        'yahoo.com' =>
            'Subject: Report Domain: timbersmart.com Submitter: yahoo.com Report-ID: <1368868092.438744>',
    );

    foreach my $dom ( sort keys %subjects ) {
        is( $recv->get_submitter_from_subject( $subjects{$dom} ),
            $dom, "get_submitter_from_subject, $dom" );
    }

    $recv->report->init();
    my $meta = $recv->report->aggregate->metadata;
    $recv->get_submitter_from_subject(
        'Subject: Report Domain: example.com Submitter: sender.example Report-ID: <uuid-test>'
    );
    is( $meta->uuid, 'uuid-test', 'subject parser sets metadata uuid' );
}

sub test_get_submitter_from_filename {
    my $recv = fresh_receiver();

    my $result = $recv->get_submitter_from_filename('submit.example!report.example!1!2');
    is( $result, 'submit.example', 'filename parser extracts envelope submitter' );
    is( $recv->{_header_from}, 'report.example', 'filename parser sets header from domain' );

    $recv->{_envelope_to} = 'existing.submitter';
    my $should_be_undef = $recv->get_submitter_from_filename('new.submitter!new.header!1!2');
    ok( !defined($should_be_undef), 'filename parser returns early when submitter already set' );
    is( $recv->{_envelope_to}, 'existing.submitter', 'existing submitter is preserved' );

    $recv = fresh_receiver();
    is( $recv->get_submitter_from_filename('rx.example!example.com!1!2!uniq.xml.gz'),
        'rx.example', 'filename parser accepts a unique-id' );

    for my $name ( 'test_dmarc.xml', 'dmarc.zip', 'rx.example!example.com.xml',
        'rx.example!example.com!start!end.xml', 'a b!example.com!1!2.xml' )
    {
        $recv = fresh_receiver();
        is( $recv->get_submitter_from_filename($name), undef, "filename parser ignores $name" );
        ok( !$recv->{_envelope_to} && !$recv->{_header_from}, "$name sets no identifiers" );
    }
}
