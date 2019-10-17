use strict;
use warnings;

use Data::Dumper;
use Test::More;
use Test::Output;
$Data::Dumper::Sortkeys = 1;

use lib 'lib';
require Mail::DMARC::Report;
require Mail::DMARC::Policy;


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
my ($report_id, $rr_id, $policy, $reasons);
my $begin = time - 10000;
my $end = time - 100;

my $mod = 'Mail::DMARC::Report::Store::SQL';
use_ok($mod);
my $sql = $mod->new;
isa_ok( $sql, $mod );

my $backend_dir = './t/travis/backends';
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
    my $provider;
    if ( $file =~ /mail-dmarc\.sql\.(\w+)\.ini/i ) {
        $provider = $1;
        eval "use DBD::$provider";
        if ($@) {
            ok( 1, "Skipping $file; DBD::$provider not available: $@" );
            next;
        }
    } else {
        next;
    }
    $sql->config( "$backend_dir/$file" );
    if ( $provider eq 'Pg' ) {
        $provider = 'PostgreSQL';
    } elsif ( $provider eq 'mysql' ) {
        $provider = 'MySQL';
    }

    test_db_connect();
    test_grammar_loaded( $provider );
    stderr_is { test_query_insert() } 'DBI error: no such table: reporting
    DBI error: table report has no column named domin
    ', 'STDERR has expected warning';
    test_query_replace();
    test_query_update();
    test_query_delete();
    test_query();
    test_query_any();
    test_ip_store_and_fetch();

    test_get_report_id();   # creates a test report
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
}
closedir( $dir );
done_testing();
exit;

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
    is_deeply( $r, [$expected], "populate_agg_records, deeply");
};

sub test_populate_agg_metadata {

    my @cols = qw(rid begin end);
    my $query = $sql->grammar->select_from( \@cols, 'report' );
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
            'report_id' => 2,
        },
        "populate_agg_metadata, deeply" ) or diag Dumper($agg);
};

sub test_get_report_policy_published {
    my $pp = $sql->get_report_policy_published( $report_id );
    $pp->apply_defaults;
    $pp->domain('recip.example.com');
    foreach ( qw/ sp pct / ) {
        delete $pp->{$_} if ! defined $pp->$_;
    };
    delete $pp->{report_id};
    delete $policy->{uri};
    ok( $pp, "get_report_policy_published");
    is_deeply( $pp, $policy, "get_report_policy_published, deeply" )
        or diag Dumper( $pp, $policy );
};

sub test_retrieve {
    my $r = $sql->retrieve;
    ok( scalar @$r, "retrieve, " . scalar @$r );

    my %tests = (
        rid         => 2,
        author      => 'Test Company',
        from_domain => 'recip.example.com',
        begin       => $begin,
        end         => $end,
    );

    foreach ( keys %tests ) {
        my $r = $sql->retrieve( $_ => $tests{$_} );
        ok( @$r, "retrieve, $_, " . scalar @$r );
    };
};

sub test_retrieve_todo {
    my $r = $sql->retrieve_todo();
    ok( $r, "retrieve_todo");
#   warn Dumper($r);
#   die $r->as_xml;
};

sub test_get_row_reason {
    ok( $sql->get_row_reason( $rr_id ), 'get_row_reason');
};

sub test_get_row_spf {
    ok( $sql->get_row_spf( $rr_id ), 'get_row_spf');
};

sub test_get_row_dkim {
    ok( $sql->get_row_dkim( $rr_id ), 'get_row_dkim');
};

sub test_get_report {
    my $reports = $sql->get_report( rid => $report_id )->{rows};

    ok( scalar @$reports, "get_report, no limits, " . scalar @$reports );

    my $limit = 10;
    my $r = $sql->get_report( rows => $limit )->{rows};
    if ( ! $r || ! scalar @$r || scalar @$r < $limit ) {
        ok( 1, "skipping author tests" );
        return;
    };

    cmp_ok( scalar @$reports, '==', $limit, "get_report, limit $limit" );

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
        $reports = $r->{rows};
        ok( scalar @$reports, "get_report, $key, $val, " . scalar @$reports );
    };
    $reports = $sql->get_report( rows => 1, sord => 'desc', sidx => 'rid'  );
    ok( $reports->{rows}, "get_report, multisearch");
};

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
    my @reasons = qw/ forwarded local_policy mailing_list other sampled_out trusted_forwarder /;
    foreach my $r ( @reasons) {
        push @$reasons, bless { type => $r, comment => "test $r comment" }, 'Mail::DMARC';
        ok( $sql->insert_rr_reason( $rr_id, $r, "test $r comment" ), "insert_rr_reason, $r" );
    }
}

sub test_insert_rr_dkim {
    ok( $sql->insert_rr_dkim( $rr_id, $dkim->[0] ), 'insert_rr_dkim' );
    ok( $sql->insert_rr_dkim( $rr_id, $dkim->[1] ), 'insert_rr_dkim' );
    ok( $sql->insert_rr_dkim( $rr_id, $dkim->[2] ), 'insert_rr_dkim' );
}

sub test_insert_rr_spf {
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
#   warn Dumper($policy);
    my $r = $sql->insert_policy_published( $report_id, $pol );
    ok( $r, 'insert_policy_published' );
}

sub test_ip_store_and_fetch {
    my @test_ips = (
        '1.1.1.1',                            '10.0.1.1',
        '2002:4c79:6240::1610:9fff:fee5:fb5', '2607:f060:b008:feed::6',
    );

    foreach my $ip (@test_ips) {

        my $query; my @cols;

        my $ipbin = $sql->any_inet_pton($ip);
        ok( $ipbin, "any_inet_pton, $ip" );

        my $pres = $sql->any_inet_ntop($ipbin);
        ok( $pres, "any_inet_ntop, $ip" );

        compare_any_inet_round_trip( $ip, $pres );

        @cols = qw(report_id source_ip disposition dkim spf header_from_did);
        $query = $sql->grammar->insert_into('report_record', \@cols);
        my $report_id = $sql->query(
            $query,
            [ 1, $ipbin, 'none', 'pass', 'pass', 1 ]
        ) or die "failed to insert?";

        @cols = qw(id source_ip);
        $query = $sql->grammar->select_from(\@cols, 'report_record');
        $query .= $sql->grammar->and_arg('id');
        my $r_ref
            = $sql->query(
            $query,
            [$report_id] );
        compare_any_inet_round_trip( $ip,
            $sql->any_inet_ntop( $r_ref->[0]{source_ip} ),
        );
    }
}

sub test_query {
    my $query = $sql->grammar->select_from( 'report', [ 'id' ] );
    ok( $sql->query( $query ), "query" );
}

sub test_query_insert {
    my $end       = time + 86400;
    my $from_did  = $sql->query(
        $sql->grammar->insert_domain, [ 'ignore.test.com' ]
    );
    my $author_id = $sql->query(
        $sql->grammar->insert_into( 'author', [ org_name ] ),
        [ 'test' ]
    );
    my $rid = $sql->query(
        $sql->grammar->insert_into( 'report', [ 'from_domain_id', 'begin', 'end', 'author_id' ] ),
        [ $from_did, $begin, $end, $author_id ]
    );
    ok( $rid, "query_insert, report, $rid" );
    my $query = $sql->grammar->delete_from('report').$sql->grammar->and_arg('id');
    ok( $sql->query( $query, [$rid] ), "query_delete" );

    # negative tests
    eval {
        $rid = $sql->query(
            $sql->grammar->insert_into( 'reporting', [ 'domain', 'begin', 'end' ] ),
            [ $test_domain, $begin, $end ] );
    };
    chomp $@;
    ok( $@, "query_insert, report, neg: $@" );

    eval {
        $rid = $sql->query(
            $sql->grammar->insert_into( 'report', [ 'domain', 'begin', 'end' ] ),
            [ 'a' x 257, 'yellow', $end ]
        );
    };
    chomp $@;
    ok( $@, "query_insert, report, neg: $@" );
}

sub test_query_replace {
    my $end   = time + 86400;

    
    my $snafus = $sql->query(
        $sql->grammar->select_from( [ 'id' ], 'report' ).$sql->grammar->and_arg('begin'),
        [ 'yellow' ]
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
    eval {
        $sql->query(
            $sql->grammar->replace_into( 'rep0rt', [ 'id', 'domain', 'begin', 'end' ] ),
            [ 1, 1, 1, 1 ]
        );
    };
    chomp $@;
    ok( $@, "replace, negative, $@" );
}

sub test_query_update {
    my $victims = $sql->query($sql->grammar->select_from( [ 'id' ], 'report' ).$sql->grammar->limit);
    foreach my $v (@$victims) {
        my $r = $sql->query( 
            $sql->grammar->update( 'report', [ 'end' ] ).$sql->grammar->and_arg( 'id' ),
            [ time, $v->{id} ] );
        ok( $r, "query_update, $r" );

        # negative test
        eval {
            $sql->query( 
                $sql->grammar->update( 'report', [ 'ed' ] ).$sql->grammar->and_arg( 'id' ),
                [ time, $v->{id} ] );
        };
        ok( $@, "query_update, neg" );
    }
}

sub test_query_delete {
    
    my $victims = $sql->query($sql->grammar->select_from( [ 'id' ], 'report' ).$sql->grammar->limit(1));
    foreach my $v (@$victims) {
        my $r = $sql->query(
            $sql->grammar->delete_from( 'report' ).$sql->grammar->and_arg( 'id' ),
            [ $v ]
        );
        ok( $r, "query_delete" );
    }

    # neg
    eval { $sql->query(
        $sql->grammar->delete_from( 'repor' ).$sql->grammar->and_arg( 'id' ),
        [ 1 ]
    ); };
    chomp $@;
    ok( $@, "delete, negative, $@" );
}

sub test_query_any {

    foreach my $table (qw/ report author domain report_record /) {
        my $r = $sql->query("SELECT id FROM $table LIMIT 1");
        ok( $r, "query, select, $table" );
    }

    # negative
    eval { $sql->query("SELECT id FROM rep0rt LIMIT 1") };
    chomp $@;
    ok( $@, "query, select, negative, $@" );
}

sub test_db_connect {
    my $dbh = $sql->db_connect();
    ok( $dbh, "db_connect" );
    isa_ok( $dbh, "DBIx::Simple" );
}

sub test_grammar_loaded {
    my $grammarName = shift;
    isa_ok( $sql->grammar(), "Mail::DMARC::Report::Store::SQL::Grammars::$grammarName" );
}

sub compare_any_inet_round_trip {
    my ( $ip, $pres ) = @_;

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
