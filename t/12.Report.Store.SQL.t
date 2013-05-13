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

my $test_domain = 'example.com';

my $mod = 'Mail::DMARC::Report::Store::SQL';
use_ok( $mod );
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

done_testing();
exit;

sub test_ip_store_and_fetch {
    my @test_ips = (
            '1.1.1.1',
            '10.0.1.1',
            '2002:4c79:6240::1610:9fff:fee5:fb5',
            '2607:f060:b008:feed::6',
            );

    foreach my $ip ( @test_ips ) {

        my $ipbin = $sql->inet_pton( $ip );
        ok( $ipbin, "inet_pton, $ip");

        my $pres = $sql->inet_ntop( $ipbin );
        ok( $pres, "inet_ntop, $ip");
        cmp_ok( $pres, 'eq', $ip, "inet_ntop, cmp");

        my $report_id = $sql->query(
            "INSERT INTO report_record ( report_id, source_ip, disposition, dkim,spf,header_from) VALUES (?,?,?,?,?,?)",
            [ 1, $ipbin, 'none','pass','pass','tnpi.net' ] )
                or die "failed to insert?";

        my $r_ref = $sql->query("SELECT id,source_ip FROM report_record WHERE id=?", [$report_id])->[0];
        cmp_ok( $sql->inet_ntop($r_ref->{source_ip}), 'eq', $ip, "inet_ntop, sql, $ip");
    };
};

sub test_query {
    ok( $sql->query("SELECT id FROM report LIMIT 1"), "query");
}

sub test_query_insert {
    my $start = time;
    my $end = time + 86400;
    my $report_id = $sql->query(
        "INSERT INTO report (domain, begin, end) VALUES (?,?,?)",
        [ $test_domain, $start, $end] );
    ok( $report_id, "query_insert, report, $report_id");

    return unless $ENV{RELEASE_TESTING}; # these tests are noisy

# negative tests
    $report_id = $sql->query(
        "INSERT INTO reporting (domain, begin, end) VALUES (?,?,?)",
        [ $test_domain, $start, $end] );
    ok( ! $report_id, "query_insert, report, neg");

    $report_id = $sql->query(
        "INSERT INTO report (domin, begin, end) VALUES (?,?,?)",
        [ 'a' x 257, 'yellow', $end] );
    ok( ! $report_id, "query_insert, report, neg") or diag Dumper($report_id);
}

sub test_query_replace {
    my $start = time;
    my $end = time + 86400;

    my $snafus = $sql->query("SELECT id FROM report WHERE begin='yellow'");
    foreach my $s ( @$snafus ) {
        ok( $sql->query( "REPLACE INTO report (id,domain, begin, end) VALUES (?,?,?,?)",
            [ $s->{id}, $test_domain, $start, $end] ),
                "query_replace");
    };
}

sub test_query_update {
    my $victims = $sql->query("SELECT id FROM report LIMIT 1");
    foreach my $v ( @$victims ) {
        my $r = $sql->query( "UPDATE report SET end=? WHERE id=?",
            [ time, $v->{id} ] );
        ok( $r, "query_update, $r");

# negative test
        ok( ! $sql->query( "UPDATE report SET ed=? WHERE id=?", [ time, $v->{id} ] ),
              "query_update, neg");
    };
}

sub test_query_delete {
    my $victims = $sql->query("SELECT id FROM report LIMIT 1");
    foreach my $v ( @$victims ) {
        my $r = $sql->query( "DELETE FROM report WHERE id=?");
        ok( $r, "query_delete");
    };
}

sub test_query_any {
    my $r = $sql->query("SELECT id FROM report LIMIT 1");
    ok( $r, "query");
}

sub test_db_connect {
    my $dbh = $sql->db_connect();
    ok( $dbh, "db_connect");
    isa_ok( $dbh, "DBIx::Simple");
}

