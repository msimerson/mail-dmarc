package Mail::DMARC::Report::Store::SQL::Grammars::MySQL;
our $VERSION = '2.20260827';
use strict;
use warnings;
use feature 'signatures';

sub new($class) {
    my $self = {};
    bless $self, $class;
    return $self;
}

sub language {
    return 'mysql';
}

sub dsn {
    return 'mysql';
}

sub and_arg( $self, $column, $operator = undef ) {
    $operator //= '=';
    return " AND $column $operator ?";
}

sub report_record_id {
    return 'SELECT id FROM report_record WHERE report_id=?';
}

sub delete_from_where_record_in( $self, $table ) {
    return "DELETE FROM $table WHERE report_record_id IN (??)";
}

sub delete_from_where_report( $self, $table ) {
    return "DELETE FROM $table WHERE report_id=?";
}

sub delete_report {
    return "DELETE FROM report WHERE id=?";
}

sub select_domain_id {
    return 'SELECT id FROM domain WHERE domain=?';
}

sub insert_domain {
    return 'INSERT INTO domain (domain) VALUES (?)';
}

sub select_author_id {
    return 'SELECT id FROM author WHERE org_name=?';
}

sub insert_author {
    return 'INSERT INTO author (org_name,email,extra_contact) VALUES (?,?,?)';
}

sub select_report_id {
    return 'SELECT id FROM report WHERE uuid=? AND author_id=?';
}

sub select_id_with_end {
    return
        'SELECT id FROM report WHERE from_domain_id=? AND end > ? AND author_id=?';
}

sub insert_report {
    return
        'INSERT INTO report (from_domain_id, begin, end, author_id, uuid) VALUES (?,?,?,?,?)';
}

sub order_by( $self, $arg, $order ) {
    return " ORDER BY $arg $order";
}

sub count_reports {
    return 'SELECT COUNT(*) FROM report';
}

sub limit( $self, $number_of_entries = undef ) {
    $number_of_entries //= 1;
    return " LIMIT $number_of_entries";
}

sub limit_args( $self, $number_of_entries = undef ) {
    $number_of_entries //= 1;
    my $return = ' LIMIT ';
    for ( my $i = 1; $i <= $number_of_entries; $i++ ) {
        $return .= '?';
        $return .= ',' if $i < $number_of_entries;
    }
    return $return;
}

sub select_report_policy_published {
    return 'SELECT * from report_policy_published WHERE report_id=?';
}

sub select_report_reason {
    return 'SELECT type,comment FROM report_record_reason WHERE report_record_id=?';
}

sub select_report_error {
    return 'SELECT error FROM report_error WHERE report_id=?';
}

sub select_report_record {
    return
        'SELECT id FROM report_record WHERE report_id=? AND source_ip=? AND count=?';
}

sub select_todo_query {
    return <<'EO_TODO_QUERY'
SELECT r.id    AS rid,
    r.begin    AS begin,
    r.end      AS end,
    a.org_name AS author,
    fd.domain  AS from_domain
FROM report r
LEFT JOIN report_record rr ON r.id=rr.report_id
LEFT JOIN author a  ON r.author_id=a.id
LEFT JOIN domain fd ON r.from_domain_id=fd.id
WHERE rr.count IS NULL
  AND rr.report_id IS NOT NULL
  AND r.end < ?
GROUP BY r.id
ORDER BY r.id ASC
EO_TODO_QUERY
        ;
}

sub select_row_spf {
    return <<"EO_SPF_ROW"
SELECT d.domain AS domain,
       s.result AS result,
       s.scope  AS scope
FROM report_record_spf s
LEFT JOIN domain d ON s.domain_id=d.id
WHERE s.report_record_id=?
EO_SPF_ROW
        ;
}

sub select_row_dkim {
    return <<"EO_DKIM_ROW"
SELECT d.domain       AS domain,
       k.selector     AS selector,
       k.result       AS result,
       k.human_result AS human_result
FROM report_record_dkim k
LEFT JOIN domain d ON k.domain_id=d.id
WHERE report_record_id=?
EO_DKIM_ROW
        ;
}

sub select_row_reason {
    return <<"EO_ROW_QUERY"
SELECT type,comment
FROM report_record_reason
WHERE report_record_id=?
EO_ROW_QUERY
        ;
}

sub select_rr_query {
    return <<'EO_ROW_QUERY'
SELECT rr.*,
    etd.domain AS envelope_to,
    efd.domain AS envelope_from,
    hfd.domain AS header_from
FROM report_record rr
LEFT JOIN domain etd ON etd.id=rr.envelope_to_did
LEFT JOIN domain efd ON efd.id=rr.envelope_from_did
LEFT JOIN domain hfd ON hfd.id=rr.header_from_did
WHERE report_id = ?
ORDER BY id ASC
EO_ROW_QUERY
        ;
}

sub select_report_query {
    return <<'EO_REPORTS'
SELECT r.id    AS rid,
    r.uuid,
    r.begin    AS begin,
    r.end      AS end,
    a.org_name AS author,
    fd.domain  AS from_domain
FROM report r
LEFT JOIN author a  ON r.author_id=a.id
LEFT JOIN domain fd ON r.from_domain_id=fd.id
WHERE 1=1
EO_REPORTS
        ;
}

sub count_filtered_report_query {
    return <<'EO_SQL'
SELECT COUNT(*)
FROM report r
LEFT JOIN author a  ON r.author_id=a.id
LEFT JOIN domain fd ON r.from_domain_id=fd.id
WHERE 1=1
EO_SQL
        ;
}

sub select_from( $self, $columns, $table ) {
    my $colStr = join( ', ', @$columns );
    return "SELECT $colStr FROM $table WHERE 1=1";
}

sub insert_error( $self, $which ) {
    if ( $which == 0 ) {
        return 'UPDATE report SET end=? WHERE id=?';
    }
    else {
        return 'INSERT INTO report_error (report_id, error) VALUES (?,?)';
    }
}

sub insert_rr_reason {
    return
        'INSERT INTO report_record_reason (report_record_id, type, comment) VALUES (?,?,?)';
}

sub insert_rr_dkim( $self, $fields ) {
    my $fields_str = join ', ', @$fields;
    return <<"EO_DKIM"
INSERT INTO report_record_dkim
    (report_record_id, $fields_str)
VALUES (??)
EO_DKIM
        ;
}

sub insert_rr_spf( $self, $fields ) {
    my $fields_str = join ', ', @$fields;
    return
        "INSERT INTO report_record_spf (report_record_id, $fields_str) VALUES(??)";
}

sub insert_rr {
    return <<'EO_ROW_INSERT'
INSERT INTO report_record
   (report_id, source_ip, count, header_from_did, envelope_to_did, envelope_from_did,
    disposition, dkim, spf)
   VALUES (??)
EO_ROW_INSERT
        ;
}

sub insert_policy_published {
    return <<"EO_RPP"
INSERT INTO report_policy_published
  (report_id, adkim, aspf, p, sp, pct, rua)
VALUES (??)
EO_RPP
        ;
}

sub insert_into( $self, $table, $cols ) {
    my $columns = join ', ', @$cols;
    return "INSERT INTO $table ($columns) VALUES (??)";
}

sub replace_into( $self, $table, $cols ) {
    my $columns = join ', ', @$cols;
    return "REPLACE INTO $table ($columns) VALUES (??)";
}

sub update( $self, $table, $cols ) {
    my $columns = join( ' = ?, ', @$cols ) . ' = ?';
    return "UPDATE $table SET $columns WHERE 1=1";
}

sub delete_from( $self, $table ) {
    return "DELETE FROM $table WHERE 1=1";
}

# Aggregate queries for the report views. Every one of these is scoped by a
# WHERE fragment the store builds from placeholders, so $where never carries
# caller-supplied text.

# The DMARC-evaluated (aligned) results live in report_record.dkim/spf, which
# are nullable; COALESCE keeps a NULL out of the comparison so that no message
# escapes all four alignment buckets.
sub outcome_buckets {
    return <<'EO_BUCKETS'
    SUM(CASE WHEN COALESCE(rr.dkim,'')='pass'  AND COALESCE(rr.spf,'')='pass'
             THEN COALESCE(rr.count,1) ELSE 0 END) AS aligned_both,
    SUM(CASE WHEN COALESCE(rr.dkim,'')='pass'  AND COALESCE(rr.spf,'')<>'pass'
             THEN COALESCE(rr.count,1) ELSE 0 END) AS aligned_dkim,
    SUM(CASE WHEN COALESCE(rr.dkim,'')<>'pass' AND COALESCE(rr.spf,'')='pass'
             THEN COALESCE(rr.count,1) ELSE 0 END) AS aligned_spf,
    SUM(CASE WHEN COALESCE(rr.dkim,'')<>'pass' AND COALESCE(rr.spf,'')<>'pass'
             THEN COALESCE(rr.count,1) ELSE 0 END) AS aligned_none,
    SUM(CASE WHEN rr.disposition='none'       THEN COALESCE(rr.count,1) ELSE 0 END) AS disp_none,
    SUM(CASE WHEN rr.disposition='quarantine' THEN COALESCE(rr.count,1) ELSE 0 END) AS disp_quarantine,
    SUM(CASE WHEN rr.disposition='reject'     THEN COALESCE(rr.count,1) ELSE 0 END) AS disp_reject
EO_BUCKETS
        ;
}

sub agg_from_clause {
    return <<'EO_FROM'
FROM report r
JOIN report_record rr ON r.id=rr.report_id
LEFT JOIN author a  ON r.author_id=a.id
LEFT JOIN domain fd ON r.from_domain_id=fd.id
EO_FROM
        ;
}

# Reporting windows are epoch seconds, so a UTC day needs no dialect date
# functions. A window spanning a day boundary is attributed to its begin day;
# reporters almost always send daily windows, so the skew is negligible.
sub select_timeseries_query( $self, $where ) {
    my $buckets = $self->outcome_buckets;
    my $from    = $self->agg_from_clause;
    return <<"EO_TIMESERIES"
SELECT (r.begin - (r.begin % 86400)) AS day,
    SUM(COALESCE(rr.count,1)) AS messages,
$buckets
$from WHERE 1=1$where
GROUP BY day
ORDER BY day ASC
EO_TIMESERIES
        ;
}

sub select_sources_query( $self, $where ) {
    my $buckets = $self->outcome_buckets;
    my $from    = $self->agg_from_clause;
    return <<"EO_SOURCES"
SELECT rr.source_ip AS source_ip,
    SUM(COALESCE(rr.count,1)) AS messages,
$buckets,
    COUNT(DISTINCT r.author_id) AS reporters,
    MIN(r.begin) AS first_seen,
    MAX(r.end)   AS last_seen
$from WHERE 1=1$where
GROUP BY rr.source_ip
ORDER BY messages DESC
EO_SOURCES
        ;
}

# Kept out of the sources query on purpose: a record with two reasons would
# join twice and double every SUM in that row.
sub select_source_reasons_query( $self, $where ) {
    my $from = $self->agg_from_clause;
    return <<"EO_REASONS"
SELECT rr.source_ip AS source_ip,
    rrr.type AS type,
    rrr.comment AS comment,
    SUM(COALESCE(rr.count,1)) AS messages
$from JOIN report_record_reason rrr ON rrr.report_record_id=rr.id
WHERE 1=1$where
GROUP BY rr.source_ip, rrr.type, rrr.comment
EO_REASONS
        ;
}

sub select_source_detail_query( $self, $where ) {
    my $from = $self->agg_from_clause;
    return <<"EO_DETAIL"
SELECT hfd.domain AS header_from,
    rr.disposition AS disposition,
    rr.dkim AS dkim,
    rr.spf  AS spf,
    SUM(COALESCE(rr.count,1)) AS messages
$from LEFT JOIN domain hfd ON hfd.id=rr.header_from_did
WHERE 1=1$where
GROUP BY hfd.domain, rr.disposition, rr.dkim, rr.spf
ORDER BY messages DESC
EO_DETAIL
        ;
}

# The d= domain and selector a source presented are what distinguish a
# misconfigured ESP from an unauthenticated spoof.
sub select_source_dkim_query( $self, $where ) {
    my $from = $self->agg_from_clause;
    return <<"EO_SRC_DKIM"
SELECT d.domain AS domain,
    k.selector AS selector,
    k.result   AS result,
    SUM(COALESCE(rr.count,1)) AS messages
$from JOIN report_record_dkim k ON k.report_record_id=rr.id
LEFT JOIN domain d ON d.id=k.domain_id
WHERE 1=1$where
GROUP BY d.domain, k.selector, k.result
ORDER BY messages DESC
EO_SRC_DKIM
        ;
}

sub select_source_spf_query( $self, $where ) {
    my $from = $self->agg_from_clause;
    return <<"EO_SRC_SPF"
SELECT d.domain AS domain,
    s.scope  AS scope,
    s.result AS result,
    SUM(COALESCE(rr.count,1)) AS messages
$from JOIN report_record_spf s ON s.report_record_id=rr.id
LEFT JOIN domain d ON d.id=s.domain_id
WHERE 1=1$where
GROUP BY d.domain, s.scope, s.result
ORDER BY messages DESC
EO_SRC_SPF
        ;
}

# Per report totals for the report list, so a row can show what it contains
# without being expanded. Returned one row per (report, From, To) rather than
# aggregated into a string, because GROUP_CONCAT, group_concat and string_agg
# are spelled differently in all three engines; the caller assembles the sets.
sub and_failing {
    return " AND COALESCE(rr.dkim,'')<>'pass' AND COALESCE(rr.spf,'')<>'pass'";
}

sub select_report_summary_query {
    my ($self) = @_;
    my $buckets = $self->outcome_buckets;
    return <<"EO_SUMMARY"
SELECT rr.report_id AS rid,
    hfd.domain AS header_from,
    etd.domain AS envelope_to,
    SUM(COALESCE(rr.count,1)) AS messages,
$buckets
FROM report_record rr
LEFT JOIN domain hfd ON hfd.id=rr.header_from_did
LEFT JOIN domain etd ON etd.id=rr.envelope_to_did
WHERE rr.report_id IN (??)
GROUP BY rr.report_id, hfd.domain, etd.domain
EO_SUMMARY
        ;
}

sub select_report_domains_query( $self, $where ) {
    return <<"EO_DOMAINS"
SELECT fd.domain AS domain,
    COUNT(*) AS reports,
    MIN(r.begin) AS first_seen,
    MAX(r.end)   AS last_seen
FROM report r
JOIN domain fd ON fd.id=r.from_domain_id
LEFT JOIN author a ON a.id=r.author_id
WHERE 1=1$where
GROUP BY fd.domain
ORDER BY fd.domain ASC
EO_DOMAINS
        ;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Store::SQL::Grammars::MySQL - Grammar for working with mysql databases.

=head1 VERSION

version 2.20260827

=head1 SYPNOSIS

Allow DMARC to be able to speak to MySQL databases.

=head1 DESCRIPTION

Uses ANSI SQL syntax, keeping the SQL as portable as possible.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=item *

Marc Bradshaw <marc@marcbradshaw.net>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2026 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
