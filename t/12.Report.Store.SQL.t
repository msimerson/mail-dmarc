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

my $mod = 'Mail::DMARC::Report::Store::SQL';
use_ok($mod);
my $sql = $mod->new;
isa_ok( $sql, $mod );

$sql->config('t/mail-dmarc.ini');

test_db_connect();
test_query_insert();
test_query_replace();
test_query_update();
test_query_delete();
test_query();
test_query_any();
test_ip_store_and_fetch();
test_insert_report_published_policy();
test_insert_report_row();
test_insert_rr_spf();
test_insert_rr_dkim();
test_insert_rr_reason();
test_insert_author_report();

done_testing();
exit;

sub test_insert_author_report {
    my %meta = (
        report_id => time,
        domain    => 'test.com',
        org_name  => 'Test Company',
        email     => 'dmarc-reporter@example.com',
        begin     => time,
        end       => time + 10,
    );
    my $report = Mail::DMARC::Report->new();
    foreach ( keys %meta ) {
        ok( $report->aggregate->metadata->$_( $meta{$_} ), "meta, $_" );
    }
    my $policy = Mail::DMARC::Policy->new("v=DMARC1; p=reject");
    $policy->rua( 'mailto:' . $sql->config->{organization}{email} );
    $policy->{domain} = 'recip.example.com';
    $report->aggregate->policy_published( $policy );
    ok( $sql->insert_author_report( $report->aggregate ), 'insert_author_report' );
}

sub test_insert_rr_reason {
    my $row_id = $sql->query('SELECT * FROM report_record LIMIT 1')->[0]{id}
        or return;
    my @reasons
        = qw/ forwarded sampled_out trusted_forwarder mailing_list local_policy other /;
    foreach my $r (@reasons) {
        ok( $sql->insert_rr_reason( $row_id, $r, 'testing' ),
            "insert_rr_reason, $r" );
    }
}

sub test_insert_rr_dkim {
    my $row_id = $sql->query('SELECT * FROM report_record LIMIT 1')->[0]{id}
        or return;
    my $dkim = {
        domain       => 'example.com',
        selector     => 'blah',
        result       => 'pass',
        human_result => 'yay'
    };

    ok( $sql->insert_rr_dkim( $row_id, $dkim ), 'insert_rr_dkim' );

    $dkim->{human_result} = undef;
    ok( $sql->insert_rr_dkim( $row_id, $dkim ), 'insert_rr_dkim' );

    delete $dkim->{human_result};
    ok( $sql->insert_rr_dkim( $row_id, $dkim ), 'insert_rr_dkim' );
}

sub test_insert_rr_spf {
    my $row_id = $sql->query('SELECT * FROM report_record LIMIT 1')->[0]{id}
        or return;
    my $spf = { domain => 'example.com', scope => 'helo', result => 'pass' };
    ok( $sql->insert_rr_spf( $row_id, $spf ), 'insert_rr_spf' );
    $spf->{scope} = 'mfrom';
    ok( $sql->insert_rr_spf( $row_id, $spf ), 'insert_rr_spf' );
    $spf->{result} = 'fail';
    ok( $sql->insert_rr_spf( $row_id, $spf ), 'insert_rr_spf' );
}

sub test_insert_report_row {
    my $rid = $sql->query('SELECT * FROM report LIMIT 1')->[0]{id} or return;
    my %identifers = (
        source_ip     => '192.1.1.1',
        header_from   => 'from.com',
        envelope_to   => 'to.com',
        envelope_from => 'from.com',
    );
    my %result = (
        disposition => 'none',
        dkim        => 'fail',
        spf         => 'pass',
    );
    ok( $sql->insert_report_row( $rid, \%identifers, \%result ),
        'insert_report_row' );
}

sub test_insert_report_published_policy {
    my $rid = $sql->query('SELECT * FROM report LIMIT 1')->[0]{id} or return;
    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=none;');
    $pol->apply_defaults;
    $pol->rua( 'mailto:' . $sql->config->{organization}{email} );
    my $r = $sql->insert_report_published_policy( $rid, $pol );
    ok( $r, 'insert_report_published_policy' );

    #   print "r: $r\n";
    #my $rpp = $sql->query('SELECT * FROM report LIMIT 1');
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
            "INSERT INTO report_record ( report_id, source_ip, disposition, dkim,spf,header_from) VALUES (?,?,?,?,?,?)",
            [ 1, $ipbin, 'none', 'pass', 'pass', 'tnpi.net' ]
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
    my $report_id = $sql->query(
        "INSERT INTO report (author_id,rcpt_domain_id,from_domain_id, begin, end) VALUES (??)",
        [ 0, 0, 0, $start, $end ]
    );
    ok( $report_id, "query_insert, report, $report_id" );

    # negative tests
    eval {
        $report_id
            = $sql->query(
            "INSERT INTO reporting (domain, begin, end) VALUES (?,?,?)",
            [ $test_domain, $start, $end ] );
    };
    chomp $@;
    ok( $@, "query_insert, report, neg: $@" );

    eval {
        $report_id
            = $sql->query(
            "INSERT INTO report (domin, begin, end) VALUES (?,?,?)",
            [ 'a' x 257, 'yellow', $end ] );
    };
    chomp $@;
    ok( $@, "query_insert, report, neg: $@" ) or diag Dumper($report_id);
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
