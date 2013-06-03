use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
require Mail::DMARC::Report;
require Mail::DMARC::Policy;

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

my $test_domain = 'example.com';
my ($report_id, $rr_id);

my $mod = 'Mail::DMARC::Report::Store::SQL';
use_ok($mod);
my $sql = $mod->new;
isa_ok( $sql, $mod );

$sql->config('t/mail-dmarc.ini');

# The general gist of the tests is:
#  test query mechanisms
#  build and store an aggregate report, as it would happen In Real Life
#  retrieve an aggregate report, as if reporting it
test_db_connect();
test_query_insert();
test_query_replace();
test_query_update();
test_query_delete();
test_query();
test_query_any();
test_ip_store_and_fetch();

test_get_report_id();   # creates a test report
test_insert_published_policy();
test_insert_rr();
test_insert_rr_spf();
test_insert_rr_dkim();
test_insert_rr_reason();

test_retrieve_todo();
test_get_author_id(3);
test_get_report();
test_get_row_reason();
test_get_row_spf();
test_get_row_dkim();

done_testing();
exit;

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
        begin     => time - 10000,
        end       => time - 100,
    );
    my $report = Mail::DMARC::Report->new();
    foreach ( keys %meta ) {
        ok( $report->aggregate->metadata->$_( $meta{$_} ), "meta, $_, set" );
    }
    my $policy = Mail::DMARC::Policy->new("v=DMARC1; p=reject");
    ok( $policy->rua( 'mailto:' . $sql->config->{organization}{email} ), "policy, rua, set");
    ok( $policy->domain( 'recip.example.com'), "policy, domain, set");
    ok( $report->aggregate->policy_published( $policy ), "policy published, set");

# find a matching report, or create a new one
    $report_id = $sql->get_report_id( $report->aggregate );
    ok( $report_id, "get_report_id, $report_id" );
}

sub test_insert_rr_reason {
    my @reasons = qw/ forwarded sampled_out trusted_forwarder mailing_list local_policy other /;
    foreach my $r (@reasons) {
        ok( $sql->insert_rr_reason( $rr_id, $r, 'test comment' ), "insert_rr_reason, $r" );
    }
}

sub test_insert_rr_dkim {
    my $dkim = {
        domain       => 'example.com',
        selector     => 'blah',
        result       => 'pass',
        human_result => 'yay'
    };

    ok( $sql->insert_rr_dkim( $rr_id, $dkim ), 'insert_rr_dkim' );

    $dkim->{human_result} = undef;
    ok( $sql->insert_rr_dkim( $rr_id, $dkim ), 'insert_rr_dkim' );

    delete $dkim->{human_result};
    ok( $sql->insert_rr_dkim( $rr_id, $dkim ), 'insert_rr_dkim' );
}

sub test_insert_rr_spf {
    my $spf = { domain => 'example.com', scope => 'helo', result => 'pass' };
    ok( $sql->insert_rr_spf( $rr_id, $spf ), 'insert_rr_spf' );
    $spf->{scope} = 'mfrom';
    ok( $sql->insert_rr_spf( $rr_id, $spf ), 'insert_rr_spf' );
    $spf->{result} = 'fail';
    ok( $sql->insert_rr_spf( $rr_id, $spf ), 'insert_rr_spf' );
}

sub test_insert_rr {
    my $record = {
        row => {
            source_ip        => '192.1.1.1',
            policy_evaluated => {
                disposition => 'none',
                dkim        => 'fail',
                spf         => 'pass',
            },
        },
        identifiers => {
            header_from   => 'from.com',
            envelope_to   => 'to.com',
            envelope_from => 'from.com',
        },
    };
    $rr_id = $sql->insert_rr( $report_id, $record );
    ok( $rr_id, "insert_rr, $rr_id" );
}

sub test_insert_published_policy {
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=none;');
    $pol->apply_defaults;
    $pol->rua( 'mailto:' . $sql->config->{organization}{email} );
    my $r = $sql->insert_published_policy( $report_id, $pol );
    ok( $r, 'insert_published_policy' );
}

sub test_ip_store_and_fetch {
    my @test_ips = (
        '1.1.1.1',                            '10.0.1.1',
        '2002:4c79:6240::1610:9fff:fee5:fb5', '2607:f060:b008:feed::6',
    );

    foreach my $ip (@test_ips) {

        my $ipbin = $sql->any_inet_pton($ip);
        ok( $ipbin, "any_inet_pton, $ip" );

        my $pres = $sql->any_inet_ntop($ipbin);
        ok( $pres, "any_inet_ntop, $ip" );

        compare_any_inet_round_trip( $ip, $pres );

        my $report_id = $sql->query(
            "INSERT INTO report_record ( report_id, source_ip, disposition, dkim,spf,header_from_did) VALUES (?,?,?,?,?,?)",
            [ 1, $ipbin, 'none', 'pass', 'pass', 1 ]
        ) or die "failed to insert?";

        my $r_ref
            = $sql->query(
            "SELECT id,source_ip FROM report_record WHERE id=?",
            [$report_id] );
        compare_any_inet_round_trip( $ip,
            $sql->any_inet_ntop( $r_ref->[0]{source_ip} ),
        );
    }
}

sub test_query {
    ok( $sql->query("SELECT id FROM report LIMIT 1"), "query" );
}

sub test_query_insert {
    my $start     = time;
    my $end       = time + 86400;
    my $from_did  = $sql->query(
        "INSERT INTO domain (domain) VALUES (?)", [ 'ignore.test.com' ]
    );
    my $rid = $sql->query(
        "INSERT INTO report (author_id, from_domain_id, begin, end) VALUES (??)",
        [ 0, $from_did, $start, $end ]
    );
    ok( $rid, "query_insert, report, $rid" );

    ok( $sql->query("DELETE FROM report WHERE id=?", [$rid] ), "query_delete" );

    # negative tests
    eval {
        $rid = $sql->query(
            "INSERT INTO reporting (domain, begin, end) VALUES (?,?,?)",
            [ $test_domain, $start, $end ] );
    };
    chomp $@;
    ok( $@, "query_insert, report, neg: $@" );

    eval {
        $rid = $sql->query(
            "INSERT INTO report (domin, begin, end) VALUES (?,?,?)",
            [ 'a' x 257, 'yellow', $end ] );
    };
    chomp $@;
    ok( $@, "query_insert, report, neg: $@" );
}

sub test_query_replace {
    my $start = time;
    my $end   = time + 86400;

    my $snafus = $sql->query("SELECT id FROM report WHERE begin='yellow'");
    foreach my $s (@$snafus) {
        ok( $sql->query(
                "REPLACE INTO report (id,domain, begin, end) VALUES (?,?,?,?)",
                [ $s->{id}, $test_domain, $start, $end ]
            ),
            "query_replace"
        );
    }

    # negative
    eval {
        $sql->query(
            "REPLACE INTO rep0rt (id,domain, begin, end) VALUES (?,?,?,?)",
            [ 1, 1, 1, 1 ] );
    };
    chomp $@;
    ok( $@, "replace, negative, $@" );
}

sub test_query_update {
    my $victims = $sql->query("SELECT id FROM report LIMIT 1");
    foreach my $v (@$victims) {
        my $r = $sql->query( "UPDATE report SET end=? WHERE id=?",
            [ time, $v->{id} ] );
        ok( $r, "query_update, $r" );

        # negative test
        eval {
            $sql->query( "UPDATE report SET ed=? WHERE id=?",
                [ time, $v->{id} ] );
        };
        ok( $@, "query_update, neg" );
    }
}

sub test_query_delete {
    my $victims = $sql->query("SELECT id FROM report LIMIT 1");
    foreach my $v (@$victims) {
        my $r = $sql->query("DELETE FROM report WHERE id=?");
        ok( $r, "query_delete" );
    }

    # neg
    eval { $sql->query("DELETE FROM repor WHERE id=?"); };
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
