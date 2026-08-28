use strict;
use warnings;
use feature 'try';
no warnings 'experimental::try';  ## no critic (ProhibitNoWarnings)

use Data::Dumper;
use Test::More;
use Test::Output;
use Test::Exception;
$Data::Dumper::Sortkeys = 1;

use lib 'lib';

# must precede the requires below, which would mask a missing load in Store::SQL
require Mail::DMARC::Report::Store::SQL;
ok( Mail::DMARC::Policy->can('new'),
    'Store::SQL loads Mail::DMARC::Policy' );
ok( Mail::DMARC::Report::Aggregate::Record->can('new'),
    'Store::SQL loads Mail::DMARC::Report::Aggregate::Record' );

require Mail::DMARC::Report;
require Mail::DMARC::Policy;
require Mail::DMARC::Report::Aggregate::Record;

my ($report_id, $rr_id, $policy, $reasons);
my $begin = time - 10000;
my $end = time - 100;

my $test_domain = 'example.com';
my $dkim = [
    {
        domain       => 'from.com',
        selector     => 'blah1',
        result       => 'pass',
        human_result => 'yay'
    },
    {
        domain       => 'example.com',
        selector     => 'blah2',
        result       => 'pass',
        human_result => undef,
    },
    {
        domain       => 'example.com',
        selector     => 'blah3',
        result       => 'pass',
    },
];
my $spf = [
    { 'domain' => 'from.com',    'result' => 'pass', 'scope' => 'helo'  },
    { 'domain' => 'from.com',    'result' => 'pass', 'scope' => 'mfrom' },
    { 'domain' => 'example.com', 'result' => 'fail', 'scope' => 'mfrom' }
];

my $mod = 'Mail::DMARC::Report::Store::SQL';
use_ok($mod);
my $sql = $mod->new;
isa_ok( $sql, $mod );

my $backend_dir = './t/backends';
opendir( my $dir, $backend_dir ) || die "Unable to view backends in $backend_dir";
# The general gist of the tests is:
#  test query mechanisms
#  build and store an aggregate report, as it would happen In Real Life
#  retrieve an aggregate report, as if reporting it
#  validate the consistency of what was stored and retrieved
# We need to run the tests for every back-end type.
#  This includes all Grammars for SQL, but it also could mean other backends
#  that aren't currently supported.
while ( my $file = readdir( $dir ) ) {
    my ($provider) = $file =~ /mail-dmarc\.sql\.(\w+)\.ini/i;
    if ( ! $provider ) {
        next;
    }
    eval "use DBD::$provider";
    if ($@) {
        ok( 1, "Skipping $provider, DBD::$provider not available" );
        next;
    }
    $sql->config( "$backend_dir/$file" );
    if ( $provider eq 'Pg' )    { $provider = 'PostgreSQL'; }
    if ( $provider eq 'mysql' ) { $provider = 'MySQL';      }

    test_db_connect( $provider ) or do {
        ok(1, "Skipping $provider, unable to connect");
        next;
    };
    test_grammar_loaded( $provider );
    test_insert_error( $provider );

    test_query_replace();
    test_query_update();
    test_query_delete();
    test_query();
    test_query_any();

    test_get_report_id();   # creates a test report
    # we need to run get_report_id before ip_store_and_fetch
    #  so that ip_store_and_fetch has a report to work with.
    test_ip_store_and_fetch();

    test_insert_policy_published();
    test_get_report_policy_published();
    test_insert_rr();
    test_insert_rr_spf();
    test_insert_rr_dkim();
    test_insert_rr_reason();

    test_retrieve();
    test_retrieve_todo();
    test_get_author_id(3);
    test_get_report();
    test_get_row_reason();
    test_get_row_spf();
    test_get_row_dkim();
    test_populate_agg_metadata();
    test_populate_agg_records();

    test_aggregates();

    test_cleanup( $provider );
}
closedir( $dir );
done_testing();
exit;

sub test_insert_error {
    my ($provider) = @_;
    my $msg = "STDERR has expected warning ($provider)";

    if ($provider eq 'PostgreSQL') {
        stderr_is { test_query_insert() } 'DBI error: ERROR:  relation "reporting" does not exist
LINE 1: INSERT INTO "reporting" ("domain", "begin", "end") VALUES ($...
                    ^
DBI error: ERROR:  column "domin" of relation "report" does not exist
LINE 1: INSERT INTO "report" ("domin", "begin", "end") VALUES ($1, $...
                              ^
', $msg;
    }
    elsif ($provider eq 'SQLite') {
        stderr_is { test_query_insert() } 'DBI error: no such table: reporting
DBI error: table report has no column named domin
', $msg;
    }
    elsif ($provider eq 'MySQL') {
        stderr_is { test_query_insert() } 'DBI error: Table \'dmarc_report.reporting\' doesn\'t exist
DBI error: Unknown column \'domin\' in \'field list\'
', $msg;
    }
}

sub test_aggregates {
    my $org   = 'Aggregate Test Co';
    my $begin = 1700000000 - ( 1700000000 % 86400 );
    my $end   = $begin + 86399;

    my $report = Mail::DMARC::Report->new();
    $report->aggregate->metadata->org_name($org);
    $report->aggregate->metadata->email('dmarc@aggregate.example');
    $report->aggregate->metadata->begin($begin);
    $report->aggregate->metadata->end($end);
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject');
    $pol->apply_defaults;
    $pol->domain('agg.example.com');
    $pol->rua('mailto:dmarc@aggregate.example');
    $report->aggregate->policy_published($pol);

    my $agg_rid = $sql->get_report_id( $report->aggregate );
    ok( $agg_rid, "test_aggregates, report created, $agg_rid" );

    # ip, count, disposition, dkim, spf, reasons, auth rows?
    my @records = (
        [ '10.0.0.1', 100, 'none',       'pass', 'pass', [],               1 ],
        [ '10.0.0.2',  40, 'none',       'pass', 'fail', ['forwarded'],    1 ],
        [ '10.0.0.3',  25, 'quarantine', 'fail', 'fail', [],               1 ],
        [ '10.0.0.3',   5, 'reject',     'fail', 'fail', [],               1 ],
        [ '10.0.0.4',  12, 'none',       'fail', 'fail', ['mailing_list'], 0 ],
        [ '10.0.0.5', 995, 'none',       'pass', 'pass', [],               1 ],
        [ '10.0.0.5',   5, 'reject',     'fail', 'fail', [],               1 ],
        [ '10.0.0.6', 890, 'none',       'pass', 'pass', [],               1 ],
        [ '10.0.0.6', 100, 'reject',     'fail', 'fail', [],               1 ],
        [ '10.0.0.7',  10, 'none',       'fail', 'fail', ['forwarded'],    1 ],
        [ '10.0.0.7',   8, 'reject',     'fail', 'fail', [],               1 ],
    );

    foreach my $r (@records) {
        my ( $ip, $count, $disp, $dkim, $spf, $reasons, $with_auth ) = @$r;
        my $rec = Mail::DMARC::Report::Aggregate::Record->new;
        $rec->identifiers(
            header_from   => 'agg.example.com',
            envelope_to   => 'rcpt.example.com',
            envelope_from => 'agg.example.com',
        );
        $rec->row(
            source_ip        => $ip,
            count            => $count,
            policy_evaluated =>
                { disposition => $disp, dkim => $dkim, spf => $spf },
        );
        my $rr_id = $sql->insert_rr( $agg_rid, $rec );
        $sql->insert_rr_reason( $rr_id, $_, 'test' ) foreach @$reasons;
        next if !$with_auth;
        $sql->insert_rr_dkim( $rr_id,
            { domain => 'agg.example.com', selector => 'sel1', result => $dkim } );
        $sql->insert_rr_spf( $rr_id,
            { domain => 'agg.example.com', scope => 'mfrom', result => $spf } );
    }

    # org_name scopes every assertion to this report alone
    my %window = ( author => $org, since => $begin - 1, until => $begin + 1 );

    test_get_timeseries( \%window, $begin );
    test_get_summary( \%window );
    test_get_sources( \%window );
    test_get_source_detail( \%window );
    test_get_report_domains();
    test_get_report_window( \%window, $begin );
    test_report_summaries( $begin );
    test_arc_override();
    test_origin_filter();
    test_reason_accounting();
}

# Reasons ride on passing records too, and one record may carry several. Both
# used to inflate the volume treated as explained by forwarding.
sub test_reason_accounting {
    my $org   = 'Reason Test Co';
    my $begin = 1670000000 - ( 1670000000 % 86400 );

    my $report = Mail::DMARC::Report->new();
    $report->aggregate->metadata->org_name($org);
    $report->aggregate->metadata->email('dmarc@reason.example');
    $report->aggregate->metadata->begin($begin);
    $report->aggregate->metadata->end( $begin + 86399 );
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject');
    $pol->apply_defaults;
    $pol->domain('reason.example.com');
    $pol->rua('mailto:dmarc@reason.example');
    $report->aggregate->policy_published($pol);

    my $rid = $sql->get_report_id( $report->aggregate );
    ok( $rid, 'test_reason_accounting, report created' );

    # ip, count, dkim, spf, [reasons], present auth
    my @records = (
        [ '10.3.0.1', 100, 'pass', 'pass', ['forwarded'],                 1 ],
        [ '10.3.0.1',  20, 'fail', 'fail', [],                            1 ],
        [ '10.3.0.2',  30, 'fail', 'fail', [ 'forwarded', 'mailing_list' ], 0 ],
        [ '10.3.0.2',  70, 'fail', 'fail', [],                            0 ],
        [ '10.3.0.3', 100, 'pass', 'pass', [],                            1 ],
        [ '10.3.0.3',  50, 'fail', 'fail', [],                            0 ],
    );

    foreach my $r (@records) {
        my ( $ip, $count, $dkim, $spf, $reasons, $auth ) = @$r;
        my $rec = Mail::DMARC::Report::Aggregate::Record->new;
        $rec->identifiers(
            header_from   => 'reason.example.com',
            envelope_to   => 'rcpt.example.com',
            envelope_from => 'reason.example.com',
        );
        $rec->row(
            source_ip        => $ip,
            count            => $count,
            policy_evaluated =>
                { disposition => 'none', dkim => $dkim, spf => $spf },
        );
        my $rr_id = $sql->insert_rr( $rid, $rec );
        $sql->insert_rr_reason( $rr_id, $_, undef ) foreach @$reasons;
        next if !$auth;
        $sql->insert_rr_dkim( $rr_id,
            { domain => 'reason.example.com', selector => 's1', result => $dkim } );
        $sql->insert_rr_spf( $rr_id,
            { domain => 'reason.example.com', scope => 'mfrom', result => $spf } );
    }

    my %window = ( author => $org, since => $begin, until => $begin );
    my %by_ip  = map { $_->{source_ip} => $_ }
        @{ $sql->get_sources(%window)->{data} };

    # 100 forwarded messages passed; only 20 failed, and none were forwarded
    is( $by_ip{'10.3.0.1'}{bucket}, 'failing',
        'a reason on a passing record does not explain a failure' );

    # 30 of 100 failing carry two reasons; summing them reaches 60 and would
    # clear the half-of-failures bar that 30 alone does not
    is( $by_ip{'10.3.0.2'}{bucket}, 'failing',
        'two reasons on one record are not counted twice' );

    # authentication belongs to the passing records only
    my $detail = $sql->get_source_detail( %window, source_ip => '10.3.0.3' );
    is( $detail->{bucket}, 'unauthenticated',
        'auth on passing records does not make failures look broken' );
}

# Reports this host authored are its outgoing queue, about other people's
# domains. They are a different population from reports others sent us, so the
# aggregate views leave them out unless asked. Also covers a NULL count, which
# the local path writes for a single not yet aggregated message.
sub test_origin_filter {
    my $org   = $sql->config->{organization}{org_name};
    my $begin = 1680000000 - ( 1680000000 % 86400 );

    my $report = Mail::DMARC::Report->new();
    $report->aggregate->metadata->org_name($org);
    $report->aggregate->metadata->email('dmarc@outgoing.example');
    $report->aggregate->metadata->begin($begin);
    $report->aggregate->metadata->end( $begin + 86399 );
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject');
    $pol->apply_defaults;
    $pol->domain('outgoing.example.com');
    $pol->rua('mailto:dmarc@outgoing.example');
    $report->aggregate->policy_published($pol);

    my $rid = $sql->get_report_id( $report->aggregate );
    ok( $rid, "test_origin_filter, outgoing report created" );

    foreach my $count ( 7, undef ) {
        my $rec = Mail::DMARC::Report::Aggregate::Record->new;
        $rec->identifiers(
            header_from   => 'outgoing.example.com',
            envelope_to   => 'rcpt.example.com',
            envelope_from => 'outgoing.example.com',
        );
        $rec->row(
            source_ip        => '10.2.0.1',
            count            => $count,
            policy_evaluated =>
                { disposition => 'none', dkim => 'pass', spf => 'pass' },
        );
        ok( $sql->insert_rr( $rid, $rec ), 'test_origin_filter, record stored' );
    }

    my %window = ( since => $begin, until => $begin );

    cmp_ok( $sql->get_summary(%window)->{current}{messages}, '==', 0,
        'get_summary, outgoing reports excluded by default' );

    # 7 from the counted record, 1 from the NULL one: the local path writes a
    # row per message and fills the count in when the report is aggregated
    cmp_ok( $sql->get_summary( %window, reports => 'outgoing' )->{current}{messages},
        '==', 8, 'get_summary, outgoing counts a NULL count as one message' );
    cmp_ok( $sql->get_summary( %window, reports => 'all' )->{current}{messages},
        '==', 8, 'get_summary, reports=all includes outgoing' );

    my $sources = $sql->get_sources( %window, reports => 'outgoing' );
    cmp_ok( $sources->{recordsTotal}, '==', 1, 'get_sources, outgoing source' );
    cmp_ok( $sources->{data}[0]{messages}, '==', 8,
        'get_sources, NULL count included' );

    cmp_ok( scalar @{ $sql->get_sources(%window)->{data} }, '==', 0,
        'get_sources, outgoing excluded by default' );

    my %domains = map { $_->{domain} => $_ }
        @{ $sql->get_report_domains->{data} };
    ok( !$domains{'outgoing.example.com'},
        'get_report_domains, outgoing domain not offered by default' );

    my %all = map { $_->{domain} => $_ }
        @{ $sql->get_report_domains( reports => 'all' )->{data} };
    ok( $all{'outgoing.example.com'},
        'get_report_domains, reports=all offers it' );

    # the report list is an audit trail, so it shows both unless asked
    my $listed = $sql->get_report( search_domain => 'outgoing.example.com' );
    cmp_ok( $listed->{recordsFiltered}, '==', 1,
        'get_report, lists outgoing by default' );
    cmp_ok(
        $sql->get_report( search_domain => 'outgoing.example.com',
            reports => 'received' )->{recordsFiltered},
        '==', 0, 'get_report, reports=received hides outgoing' );
}

# ARC carries authentication across a forwarding hop. A receiver that overrode
# its policy on a passing chain reports local_policy with the result in free
# text, so those failures are explained and not the operator's to chase.
sub test_arc_override {
    my $org   = 'ARC Test Co';
    my $begin = 1690000000 - ( 1690000000 % 86400 );

    my $report = Mail::DMARC::Report->new();
    $report->aggregate->metadata->org_name($org);
    $report->aggregate->metadata->email('dmarc@arc.example');
    $report->aggregate->metadata->begin($begin);
    $report->aggregate->metadata->end( $begin + 86399 );
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject');
    $pol->apply_defaults;
    $pol->domain('arc.example.com');
    $pol->rua('mailto:dmarc@arc.example');
    $report->aggregate->policy_published($pol);

    my $rid = $sql->get_report_id( $report->aggregate );
    ok( $rid, "test_arc_override, report created" );

    my @records = (
        [ '10.1.0.1', 20, 'arc=pass' ],
        [ '10.1.0.2', 20, 'arc=fail' ],
        [ '10.1.0.3', 20, undef ],
        [ '10.1.0.4', 20, 'arc=pass as[1].d=example.org as[1].s=sel' ],
    );

    foreach my $r (@records) {
        my ( $ip, $count, $comment ) = @$r;
        my $rec = Mail::DMARC::Report::Aggregate::Record->new;
        $rec->identifiers(
            header_from   => 'arc.example.com',
            envelope_to   => 'rcpt.example.com',
            envelope_from => 'arc.example.com',
        );
        $rec->row(
            source_ip        => $ip,
            count            => $count,
            policy_evaluated =>
                { disposition => 'none', dkim => 'fail', spf => 'fail' },
        );
        my $rr_id = $sql->insert_rr( $rid, $rec );
        $sql->insert_rr_reason( $rr_id, 'local_policy', $comment );
    }

    my $sources = $sql->get_sources( author => $org,
        since => $begin, until => $begin );
    my %by_ip = map { $_->{source_ip} => $_ } @{ $sources->{data} };

    is( $by_ip{'10.1.0.1'}{bucket}, 'forwarded',
        'arc=pass explains the failures' );
    is( $by_ip{'10.1.0.4'}{bucket}, 'forwarded',
        'arc=pass with chain detail explains the failures' );
    is( $by_ip{'10.1.0.2'}{bucket}, 'failing',
        'arc=fail does not explain the failures' );
    is( $by_ip{'10.1.0.3'}{bucket}, 'failing',
        'local_policy with no comment does not explain the failures' );

    is( $by_ip{'10.1.0.1'}{reasons}[0]{comment}, 'arc=pass',
        'reason comment is carried through' );
}

sub test_report_summaries {
    my ($begin) = @_;

    my $plain = $sql->get_report( search_author => 'Aggregate Test Co',
        since => $begin, until => $begin );
    ok( !exists $plain->{data}[0]{summary},
        'get_report, no summary unless asked' );

    my $r = $sql->get_report( search_author => 'Aggregate Test Co',
        since => $begin, until => $begin, summary => 1 );
    my $summary = $r->{data}[0]{summary};

    ok( $summary, 'get_report, summary attached' ) or return;
    cmp_ok( $summary->{messages}, '==', 2190, 'report summary, messages' );
    cmp_ok( $summary->{aligned_both}, '==', 1985, 'report summary, aligned_both' );
    cmp_ok( $summary->{aligned_none}, '==', 165,  'report summary, aligned_none' );
    cmp_ok(
        $summary->{aligned_both} + $summary->{aligned_dkim}
            + $summary->{aligned_spf} + $summary->{aligned_none},
        '==', $summary->{messages},
        'report summary, buckets partition the report'
    );

    # the domain sets are assembled in Perl, because the three engines spell
    # string aggregation differently
    is_deeply( $summary->{header_from}, ['agg.example.com'],
        'report summary, From domains' );
    is_deeply( $summary->{envelope_to}, ['rcpt.example.com'],
        'report summary, To domains' );
}

sub test_get_report_window {
    my ( $window, $begin ) = @_;

    my $inside = $sql->get_report( search_author => 'Aggregate Test Co',
        since => $begin, until => $begin );
    cmp_ok( $inside->{recordsFiltered}, '==', 1,
        'get_report, window includes a report beginning in it' );

    my $before = $sql->get_report( search_author => 'Aggregate Test Co',
        since => $begin + 1, until => $begin + 86400 );
    cmp_ok( $before->{recordsFiltered}, '==', 0,
        'get_report, window excludes a report beginning before it' );

    # A junk bound is dropped rather than silently matching nothing, so a
    # hand-edited query string cannot make the list look empty.
    my $junk = $sql->get_report( search_author => 'Aggregate Test Co',
        since => 'yesterday' );
    cmp_ok( $junk->{recordsFiltered}, '==', 1,
        'get_report, non-numeric window bound ignored' );
}

sub test_get_timeseries {
    my ( $window, $begin ) = @_;
    my $days = $sql->get_timeseries(%$window)->{data};

    cmp_ok( scalar @$days, '==', 1, 'get_timeseries, one day bucket' );
    cmp_ok( $days->[0]{day}, '==', $begin, "get_timeseries, day is $begin" );
    cmp_ok( $days->[0]{messages}, '==', 2190, 'get_timeseries, 2190 messages' );
}

sub test_get_summary {
    my ($window) = @_;
    my $summary = $sql->get_summary(%$window);
    my $now     = $summary->{current};

    my %expect = (
        messages        => 2190,
        aligned_both    => 1985,
        aligned_dkim    => 40,
        aligned_spf     => 0,
        aligned_none    => 165,
        disp_none       => 2047,
        disp_quarantine => 25,
        disp_reject     => 118,
        dmarc_pass      => 2025,
        days            => 1,
    );
    foreach my $field ( sort keys %expect ) {
        cmp_ok( $now->{$field}, '==', $expect{$field},
            "get_summary, $field is $expect{$field}" );
    }

    # the buckets partition the volume; a NULL slipping into a comparison
    # would silently drop messages from all four
    cmp_ok(
        $now->{aligned_both} + $now->{aligned_dkim}
            + $now->{aligned_spf} + $now->{aligned_none},
        '==', $now->{messages}, 'get_summary, alignment buckets partition volume'
    );
    cmp_ok(
        $now->{disp_none} + $now->{disp_quarantine} + $now->{disp_reject},
        '==', $now->{messages}, 'get_summary, dispositions partition volume'
    );

    ok( $summary->{previous}, 'get_summary, previous window present' );
    cmp_ok( $summary->{previous}{messages}, '==', 0,
        'get_summary, previous window is empty' );

    my $unbounded = $sql->get_summary( author => 'Aggregate Test Co' );
    ok( !$unbounded->{previous},
        'get_summary, no previous window without both bounds' );
}

sub test_get_sources {
    my ($window) = @_;
    my $sources = $sql->get_sources(%$window);

    cmp_ok( $sources->{recordsTotal}, '==', 7, 'get_sources, 7 sources' );
    cmp_ok( $sources->{messagesTotal}, '==', 2190,
        'get_sources, messagesTotal covers the window' );

    my @ips = map { $_->{source_ip} } @{ $sources->{data} };
    is_deeply( \@ips, [ '10.0.0.6', '10.0.0.3', '10.0.0.7', '10.0.0.4',
            '10.0.0.5', '10.0.0.1', '10.0.0.2' ],
        'get_sources, ranked by failing volume' )
        or diag "got: @ips";

    my %by_ip = map { $_->{source_ip} => $_ } @{ $sources->{data} };

    cmp_ok( $by_ip{'10.0.0.3'}{messages}, '==', 30,
        'get_sources, two records for one IP are summed' );
    cmp_ok( $by_ip{'10.0.0.3'}{reporters}, '==', 1, 'get_sources, reporters' );

    is( $by_ip{'10.0.0.1'}{bucket}, 'aligned',   'get_sources, bucket aligned' );
    is( $by_ip{'10.0.0.2'}{bucket}, 'aligned',
        'get_sources, DKIM-only pass is aligned' );
    is( $by_ip{'10.0.0.3'}{bucket}, 'failing',   'get_sources, bucket failing' );
    is( $by_ip{'10.0.0.4'}{bucket}, 'forwarded',
        'get_sources, failures explained by forwarding' );

    # 5 of 1000 fail: under the tolerance, so not worth an operator's attention
    is( $by_ip{'10.0.0.5'}{bucket}, 'aligned',
        'get_sources, failures under tolerance stay aligned' );
    cmp_ok( $by_ip{'10.0.0.5'}{aligned_none}, '==', 5,
        'get_sources, tolerated failures are still counted' );

    # 100 of 1000 fail: over the tolerance
    is( $by_ip{'10.0.0.6'}{bucket}, 'failing',
        'get_sources, failures over tolerance are failing' );

    # forwarding explains 10 of 18 failures, the bulk but not all of them
    is( $by_ip{'10.0.0.7'}{bucket}, 'forwarded',
        'get_sources, forwarding need only explain the bulk' );

    is_deeply( $by_ip{'10.0.0.4'}{reasons},
        [ { type => 'mailing_list', comment => 'test', messages => 12 } ],
        'get_sources, reasons attached' );

    my $by_volume = $sql->get_sources( %$window, sort_col => 'messages' );
    my @ranked = map { $_->{source_ip} } @{ $by_volume->{data} };
    is_deeply( \@ranked, [ '10.0.0.5', '10.0.0.6', '10.0.0.1', '10.0.0.2',
            '10.0.0.3', '10.0.0.7', '10.0.0.4' ],
        'get_sources, sort_col messages' )
        or diag "got: @ranked";

    my $page = $sql->get_sources( %$window, start => 1, length => 2 );
    cmp_ok( $page->{recordsTotal}, '==', 7,
        'get_sources, recordsTotal ignores paging' );
    cmp_ok( $page->{messagesTotal}, '==', 2190,
        'get_sources, messagesTotal ignores paging' );
    cmp_ok( scalar @{ $page->{data} }, '==', 2, 'get_sources, page of 2' );
    is( $page->{data}[0]{source_ip}, '10.0.0.3', 'get_sources, paging offset' );
}

sub test_get_source_detail {
    my ($window) = @_;

    my $broken = $sql->get_source_detail( %$window, source_ip => '10.0.0.3' );
    is( $broken->{bucket}, 'broken',
        'get_source_detail, presented auth that failed is broken' );
    cmp_ok( scalar @{ $broken->{records} }, '==', 2,
        'get_source_detail, one row per disposition' );
    cmp_ok( $broken->{records}[0]{messages}, '==', 25,
        'get_source_detail, records ranked by volume' );
    is( $broken->{dkim}[0]{selector}, 'sel1',
        'get_source_detail, DKIM selector' );
    cmp_ok( $broken->{dkim}[0]{messages}, '==', 30,
        'get_source_detail, DKIM volume summed' );
    is( $broken->{spf}[0]{scope}, 'mfrom', 'get_source_detail, SPF scope' );

    my $spoof = $sql->get_source_detail( %$window, source_ip => '10.0.0.4' );
    is( $spoof->{bucket}, 'unauthenticated',
        'get_source_detail, no auth presented is unauthenticated' );
    cmp_ok( scalar @{ $spoof->{dkim} }, '==', 0, 'get_source_detail, no DKIM' );

    my $clean = $sql->get_source_detail( %$window, source_ip => '10.0.0.1' );
    is( $clean->{bucket}, 'aligned', 'get_source_detail, bucket aligned' );

    throws_ok { $sql->get_source_detail(%$window) } qr/missing source_ip/,
        'get_source_detail, source_ip required';
    throws_ok { $sql->get_timeseries( 'odd' ) } qr/invalid parameters/,
        'get_timeseries, odd parameter list';
}

sub test_get_report_domains {
    my $domains = $sql->get_report_domains->{data};

    ok( @$domains, 'get_report_domains, ' . scalar(@$domains) . ' domains' );
    my ($agg) = grep { 'agg.example.com' eq $_->{domain} } @$domains;
    ok( $agg, 'get_report_domains, includes agg.example.com' );
    cmp_ok( $agg->{reports}, '>=', 1, 'get_report_domains, report count' );
    cmp_ok( $agg->{first_seen}, '>', 0, 'get_report_domains, first_seen' );
}

sub test_cleanup {
    my ($provider) = @_;

    if ( $provider eq 'PostgreSQL' ) {
        ok ( $sql->query(
            'TRUNCATE author, domain, report,
                report_error, report_policy_published,
                report_record, report_record_dkim, report_record_reason,
                report_record_spf RESTART IDENTITY;'
        ), 'truncate_testing_pg_database' );
        return;
    }

    my $reports = $sql->get_report()->{data};
    foreach my $report (@$reports) {
        # print Dumper($report);
        $sql->delete_report($report->{rid});
    }
    $reports = $sql->get_report()->{data};
    if (@$reports) {
        # print Dumper($reports);
        die "failed to delete reports!\n";
    }

    if ($provider eq 'SQLite') {
        unlink "t/reports-test.sqlite";
    }
}

sub test_populate_agg_records {
    my $agg = Mail::DMARC::Report::Aggregate->new();

    my $r = $sql->populate_agg_records( \$agg, $report_id );
    ok( $r, "populate_agg_records");

    # human result is returned undef from SQL, but absent during insertion
    # delete $r->[0]{auth_results}{dkim}[2]{human_result};
    my $expected = Mail::DMARC::Report::Aggregate::Record->new(
            auth_results => {
                'dkim' => $dkim,
                'spf'  => $spf,
            },
            identifiers => {
                header_from   => 'from.com',
                envelope_to   => 'to.com',
                envelope_from => 'from.com',
            },
            row => {
                'count' => 1,
                'policy_evaluated' => {
                    disposition => 'none',
                    dkim        => 'pass',
                    spf         => 'pass',
                    reason      => $reasons,
                },
                'source_ip' => '192.1.1.1'
            },
        );
    $expected->auth_results->dkim->[2]{human_result} = undef;
    is_deeply( $r, [$expected], "populate_agg_records, deeply")
        or diag Dumper($r, [$expected]);
}

sub test_populate_agg_metadata {
    my $query = $sql->grammar->select_from( [ 'id AS rid', 'begin', 'end' ], 'report' );
    $query .= $sql->grammar->and_arg( 'id' );

    my $report = $sql->query( $query, [ $report_id ] )->[0];

    my $agg = Mail::DMARC::Report::Aggregate->new();
    ok( $sql->populate_agg_metadata( \$agg, \$report ), "populate_agg_metadata");
    is_deeply(
        $agg->metadata,
        {
            'config_file' => 'mail-dmarc.ini',
            'date_range' => {
                                'begin' => $report->{begin},
                                'end'   => $report->{end},
                            },
            'email' => 'noreply@example.com',
            'extra_contact_info' => 'http://www.example.com/dmarc-policy/',
            'org_name' => 'My Great Company',
            'report_id' => $report_id,
        },
        "populate_agg_metadata, deeply" ) or diag Dumper($agg);
}

sub test_get_report_policy_published {
    my $pp = $sql->get_report_policy_published( $report_id );
    $pp->apply_defaults;
    $pp->domain('recip.example.com');
    foreach ( qw/ sp pct / ) {
        delete $pp->{$_} if ! defined $pp->$_;
    };
    delete $pp->{report_id};
    delete $policy->{uri};
    delete $pp->{id};
    ok( $pp, "get_report_policy_published");
    is_deeply( $pp, $policy, "get_report_policy_published, deeply" )
        or diag Dumper( $pp, $policy );
}

sub test_retrieve {
    my $r = $sql->retrieve;
    ok( @$r, "retrieve, " . @$r );

    my %tests = (
        rid         => $report_id,
        author      => 'Test Company',
        from_domain => 'recip.example.com',
        begin       => $begin,
        end         => $end,
    );

    foreach ( keys %tests ) {
        my $r = $sql->retrieve( $_ => $tests{$_} );
        ok( @$r, "retrieve, $_, " . @$r );
    };

    # Test negation with '!' prefix
    my $r_neg_author = $sql->retrieve( author => '!NonExistentAuthor' );
    ok( @$r_neg_author >= @$r, "retrieve, negate author excludes nothing when non-matching" );

    my $r_neg_domain = $sql->retrieve( from_domain => '!nonexistent.example.com' );
    ok( @$r_neg_domain >= @$r, "retrieve, negate from_domain excludes nothing when non-matching" );

    my $r_excl_author = $sql->retrieve( author => '!Test Company' );
    ok( @$r_excl_author < @$r || @$r_excl_author == 0,
        "retrieve, negate author excludes matching records" );

    my $r_sorted = $sql->retrieve( sort_by => 'author', sort_order => 'ASC', limit => 1 );
    ok( ref($r_sorted) eq 'ARRAY' && @$r_sorted <= 1,
        'retrieve supports sort and limit' );

    my $r_fallback = $sql->retrieve( sort_by => 'bogus', sort_order => 'invalid', limit => 1 );
    ok( ref($r_fallback) eq 'ARRAY',
        'retrieve falls back to default sort options for invalid values' );

    throws_ok { $sql->retrieve( limit => 0 ) } qr/limit must be a positive integer/i,
        'retrieve croaks when limit is zero';

    throws_ok { $sql->retrieve( limit => 'abc' ) } qr/limit must be a positive integer/i,
        'retrieve croaks when limit is non-numeric';
}

sub test_retrieve_todo {
    my $r = $sql->retrieve_todo();
    ok( $r, "retrieve_todo");
    for ( 1 .. @$r ) {
        ok( $sql->next_todo(), 'next_todo returns cached report' );
    }
    ok( !defined $sql->next_todo(), 'next_todo returns undef when cached list is exhausted' );
    ok( !exists $sql->{_todo_list}, 'next_todo clears exhausted cache' );
    # warn Dumper($r);
    # die $r->as_xml;
}

sub test_get_row_reason {
    ok( $sql->get_row_reason( $rr_id ), 'get_row_reason');
}

sub test_get_row_spf {
    ok( $sql->get_row_spf( $rr_id ), 'get_row_spf');
}

sub test_get_row_dkim {
    ok( $sql->get_row_dkim( $rr_id ), 'get_row_dkim');
}

sub test_get_report {
    my $reports = $sql->get_report( rid => $report_id )->{data};

    ok( @$reports, "get_report, no limits, " . @$reports );

    my $limit = 10;
    my $r = $sql->get_report( length => $limit )->{data};
    if ( ! $r || ! @$r || @$r < $limit ) {
        ok( 1, "skipping author tests" );
        return;
    };

    cmp_ok( @$reports, '==', $limit, "get_report, limit $limit" );

    my @queries = (
            author      => 'The Art Farm',
            author      => 'google.com',
            from_domain => 'theartfarm.com',
            recipient   => 'google.com',
            recipient   => 'yahoo.com',
            );

    while ( my $key = shift @queries ) {
        my $val = shift @queries;
        $r = $sql->get_report( $key => $val );
        $reports = $r->{data};
        ok( @$reports, "get_report, $key, $val, " . @$reports );
    };
    $reports = $sql->get_report( length => 1, sort_dir => 'desc', sort_col => 'r.id' );
    ok( $reports->{data}, "get_report, multisearch");
}

sub test_get_author_id {
    my $times = shift or return;
    my %meta = (
        org_name           => "Test $times Company",
        email              => 'dmarc-reporter@example.com',
        extra_contact_info => undef,
        report_id          => undef,
        begin              => time,
        end                => time + 10,
    );

    my $report = Mail::DMARC::Report->new();
    foreach ( keys %meta ) {
        next if ! defined $_;
        next if ! defined $meta{$_};
        ok( $report->aggregate->metadata->$_( $meta{$_} ), "meta, $_, set" );
    }

    my $policy = Mail::DMARC::Policy->new("v=DMARC1; p=reject");
    ok( $policy->rua( 'mailto:' . $sql->config->{organization}{email} ), "policy, rua, set");
    ok( $policy->domain( 'recip.example.com'), "policy, domain, set");
    ok( $report->aggregate->policy_published( $policy ), "policy published, set");

    # find a matching report, or create a new one
    my $rid = $sql->get_report_id( $report->aggregate );
    ok( $rid, "get_report_id, $rid" );

    my $authors = $sql->get_author_id( $report->aggregate->metadata );
    test_get_author_id($times - 1);
}

sub test_get_report_id {
    my %meta = (
        org_name  => 'Test Company',
        email     => 'dmarc-reporter@example.com',
        begin     => $begin,
        end       => $end,
    );
    my $report = Mail::DMARC::Report->new();
    foreach ( keys %meta ) {
        ok( $report->aggregate->metadata->$_( $meta{$_} ), "meta, $_, set" );
    }
    $policy = Mail::DMARC::Policy->new("v=DMARC1; p=reject");
    $policy->apply_defaults;
    ok( $policy->rua( 'mailto:' . $sql->config->{organization}{email} ), "policy, rua, set");
    ok( $policy->domain( 'recip.example.com'), "policy, domain, set");
    ok( $report->aggregate->policy_published( $policy ), "policy published, set");

    # find a matching report, or create a new one
    $report_id = $sql->get_report_id( $report->aggregate );
    ok( $report_id, "get_report_id, $report_id" );
}

sub test_insert_rr_reason {
    ok ( $rr_id, "at_test_insert_rr_reason with $rr_id");
    my @reasons = qw/ forwarded local_policy mailing_list other sampled_out trusted_forwarder /;
    $reasons = undef;
    foreach my $r ( @reasons) {
        push @$reasons, bless { type => $r, comment => "test $r comment" }, 'Mail::DMARC';
        my $rrid = $sql->insert_rr_reason( $rr_id, $r, "test $r comment" );
        ok($rrid , "insert_rr_reason, $r" ) or diag Dumper($rrid);
    }
}

sub test_insert_rr_dkim {
    ok ( $rr_id, "at_test_insert_rr_dkim with $rr_id");
    ok( $sql->insert_rr_dkim( $rr_id, $dkim->[0] ), 'insert_rr_dkim' );
    ok( $sql->insert_rr_dkim( $rr_id, $dkim->[1] ), 'insert_rr_dkim' );
    ok( $sql->insert_rr_dkim( $rr_id, $dkim->[2] ), 'insert_rr_dkim' );
}

sub test_insert_rr_spf {
    ok ( $rr_id, "at_test_insert_rr_spf with $rr_id");
    foreach ( @$spf ) {
        ok( $sql->insert_rr_spf( $rr_id, $_ ), 'insert_rr_spf' );
    };
}

sub test_insert_rr {
    my $record = Mail::DMARC::Report::Aggregate::Record->new;

    $record->identifiers(
            header_from   => 'from.com',
            envelope_to   => 'to.com',
            envelope_from => 'from.com',
        );

    $record->row(
            source_ip        => '192.1.1.1',
            policy_evaluated => {
                disposition => 'none',
                dkim        => 'pass',
                spf         => 'pass',
            }
        );

    $rr_id = $sql->insert_rr( $report_id, $record );
    ok( $rr_id, "insert_rr, $rr_id" );
}

sub test_insert_policy_published {
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=reject');
    $pol->apply_defaults;
    $pol->rua( 'mailto:' . $sql->config->{organization}{email} );
    # warn Dumper($policy);
    my $r = $sql->insert_policy_published( $report_id, $pol );
    ok( $r, 'insert_policy_published' );
}

sub test_ip_store_and_fetch {
    my @test_ips = (
        '1.1.1.1',                            '10.0.1.1',
        '2002:4c79:6240::1610:9fff:fee5:fb5', '2607:f060:b008:feed::6',
    );

    foreach my $ip (@test_ips) {
        my $ipbin = $ip;
        if ( $sql->grammar->language ne 'postgresql' ) {
            $ipbin = $sql->any_inet_pton($ip);
            ok( $ipbin, "any_inet_pton, $ip" );

            my $pres = $sql->any_inet_ntop($ipbin);
            ok( $pres, "any_inet_ntop, $ip" );

            compare_any_inet_round_trip( $ip, $pres );
        }

        my $r_id = $sql->query(
            $sql->grammar->insert_into( 'report_record', [ 'report_id', 'source_ip', 'disposition', 'dkim', 'spf', 'header_from_did' ] ),
            [ $report_id, $ipbin, 'none', 'pass', 'pass', 1 ]
        ) or die "failed to insert?";

        my $rr_ref = $sql->query(
            $sql->grammar->select_from( [ 'id', 'source_ip' ], 'report_record' ) . $sql->grammar->and_arg('id'),
            [ $r_id ]
        );
        ok( @$rr_ref, 'records_retrieved' );
        if ( $sql->grammar->language eq 'postgresql' ) {
            compare_any_inet_round_trip( $ip, $rr_ref->[0]{source_ip} );
        } else {
            compare_any_inet_round_trip( $ip,
                $sql->any_inet_ntop( $rr_ref->[0]{source_ip} ),
            );
        }

        $sql->query(
            $sql->grammar->delete_from( 'report_record' ).$sql->grammar->and_arg( 'id' ),
            [ $r_id ]
        );
    }
}

sub test_query {
    ok( $sql->query( $sql->grammar->select_from( [ 'id' ], 'report' ) ), "query" );
}

sub test_query_insert {
    my $end       = time + 86400;
    my $from_did  = $sql->query(
        $sql->grammar->insert_domain, [ 'ignore.test.com' ]
    );
    my $author_id = $sql->query(
        $sql->grammar->insert_into( 'author', [ 'org_name' ] ),
        [ 'test' ]
    );
    my $rid = $sql->query(
        $sql->grammar->insert_into( 'report', [ 'from_domain_id', 'begin', 'end', 'author_id' ] ),
        [ $from_did, $begin, $end, $author_id ]
    );
    ok( $rid, "query_insert, report, $rid" );

    ok( $sql->delete_report($rid), "delete_report, report, $rid");

    # negative tests
    dies_ok {
        $sql->query(
            $sql->grammar->insert_into( 'reporting', [ 'domain', 'begin', 'end' ] ),
            [ $test_domain, $begin, $end ] );
    } "query_insert, neg, bad table";

    dies_ok {
        $sql->query(
            $sql->grammar->insert_into( 'report', [ 'domin', 'begin', 'end' ] ),
            [ 'a' x 257, 'yellow', $end ]
        );
    } "query_insert, neg, bad column";
}

sub test_query_replace {
    my $end   = time + 86400;

    my $snafus = $sql->query(
        $sql->grammar->select_from( [ 'id' ], 'report' ).$sql->grammar->and_arg('begin'),
        [ $begin ]
    );
    foreach my $s (@$snafus) {
        ok( $sql->query(
                $sql->grammar->replace_into( 'report', [ 'id', 'domain', 'begin', 'end' ] ),
                [ $s->{id}, $test_domain, $begin, $end ]
            ),
            "query_replace"
        );
    }

    # negative
    dies_ok {
        $sql->query(
            $sql->grammar->replace_into( 'rep0rt', [ 'id', 'domain', 'begin', 'end' ] ),
            [ 1, 1, 1, 1 ]
        );
    } "replace, negative";
}

sub test_query_update {
    my $victims = $sql->query($sql->grammar->select_from( [ 'id' ], 'report' ).$sql->grammar->limit);
    foreach my $v (@$victims) {
        my $r = $sql->query(
            $sql->grammar->update( 'report', [ 'end' ] ).$sql->grammar->and_arg( 'id' ),
            [ time, $v->{id} ] );
        ok( $r, "query_update, $r" );

        # negative test
        dies_ok {
            $sql->query(
                $sql->grammar->update( 'report', [ 'ed' ] ).$sql->grammar->and_arg( 'id' ),
                [ time, $v->{id} ] );
        } "query_update, neg";
    }
}

sub test_query_delete {

    my $victims = $sql->query($sql->grammar->select_from( [ 'id' ], 'report' ).$sql->grammar->limit(1));
    foreach my $v (@$victims) {
        # print "test_query_delete victim: $v->{id}\n";
        try {
            my $r = $sql->delete_report($v->{id});
            ok( $r, "query_delete $v->{id}" );
        }
        catch ($error) {
            warn $error;
        }
    }

    # neg
    dies_ok {
        $sql->query(
            $sql->grammar->delete_from( 'repor' ).$sql->grammar->and_arg( 'id' ),
            [ 1 ]
        );
    } "delete, negative";
}

sub test_query_any {

    foreach my $table (qw/ report author domain report_record /) {
        my $r = $sql->query("SELECT id FROM $table LIMIT 1");
        ok( $r, "query, select, $table" );
    }

    # negative
    dies_ok { $sql->query("SELECT id FROM rep0rt LIMIT 1") }
        "query, select, negative";
}

sub test_db_connect {
    my ($grammar) = @_;
    my $dbh;
    my $error = '';
    try {
        $dbh = $sql->db_connect();
    }
    catch ($e) {
        $error = $e;
    }
    if ($error) {
        warn $error;
        return 0;
    }

    ok( $dbh, "db_connect: $grammar" );
    isa_ok( $dbh, "DBIx::Simple" );
    return 1;
}

sub test_grammar_loaded {
    my ($grammarName) = @_;
    isa_ok( $sql->grammar(), "Mail::DMARC::Report::Store::SQL::Grammars::$grammarName" );
}

sub compare_any_inet_round_trip {
    my ($ip, $pres) = @_;

    if ( $pres eq $ip ) {
        cmp_ok( $pres, 'eq', $ip, "any_inet_ntop, round_trip, $ip" );
    }
    else {
        # on some systems, a :: pattern gets a zero inserted. Mimic that
        my $zero_filled = $ip;
        $zero_filled =~ s/::/:0:/g;
        cmp_ok( $pres, 'eq', $zero_filled,
            "any_inet_ntop, round_trip, zero-pad, $ip" )
            or diag "presentation: $zero_filled\nresult: $pres";
    }
}
