package Mail::DMARC::Report::Store::SQL::Grammars::PostgreSQL;
# VERSION
use strict;
use warnings;

sub new {
   my $class = shift;
   my $self = { };
   bless $self, $class;
   return $self;
}

sub language {
    return 'postgresql';
}

sub dsn {
    return 'Pg';
}

sub and_arg {
    my ($self, $column, $operator) = @_;
    $operator //= '=';
    $column =~ s/(\w+)\.(\w+)/"$1"."$2"/ if $column =~ /\./;

    return " AND $column $operator ?";
}

sub report_record_id {
    return 'SELECT "id" FROM "report_record" WHERE "report_id"=?';
}

sub delete_from_where_record_in {
    my ($self, $table, $row_ids) = @_;
    return "DELETE FROM \"$table\" WHERE \"report_record_id\" IN ($row_ids)"
}

sub delete_from_where_report {
    my ($self, $table) = @_;
    return "DELETE FROM \"$table\" WHERE \"report_id\"=?";
}

sub delete_report {
    return "DELETE FROM \"report\" WHERE \"id\"=?";
}

sub select_domain_id {
    return 'SELECT "id" FROM "domain" WHERE "domain"=?';
}

sub select_report_id {
    return 'SELECT "id" FROM "report" WHERE "uuid"=? AND "author_id"=?';
}

sub select_id_with_end {
    return 'SELECT "id" FROM "report" WHERE "from_domain_id"=? AND "end" > ? AND "author_id"=?';
}

sub insert_domain {
    return 'INSERT INTO "domain" ("domain") VALUES (?)';
}

sub select_author_id {
    return 'SELECT "id" FROM "author" WHERE "org_name"=?';
}

sub insert_author {
    return 'INSERT INTO "author" ("org_name", "email", "extra_contact") VALUES (?,?,?)';
}

sub insert_report {
    return 'INSERT INTO "report" ("from_domain_id", "begin", "end", "author_id", "uuid") VALUES (?,?,?,?,?)';
}

sub order_by {
    my ($self, $arg, $order) = @_;
    return " ORDER BY \"$arg\" $order";
}

sub count_reports {
    return 'SELECT COUNT(*) FROM "report"';
}

sub limit {
    my ($self, $number_of_entries) = @_;
    $number_of_entries //= 1;
    return " LIMIT $number_of_entries";
}

sub limit_args {
    my ($self, $number_of_entries) = @_;
    my $return = ' LIMIT ?';
    $number_of_entries //= 1;
    if ($number_of_entries > 1) {
        $return = " OFFSET ? $return";
    }
    return $return;
}

sub select_report_policy_published {
    return 'SELECT * from "report_policy_published" WHERE "report_id"=?';
}

sub select_report_reason {
    return 'SELECT "type","comment" FROM "report_record_reason" WHERE "report_record_id"=?';
}

sub select_report_error {
    return 'SELECT "error" FROM "report_error" WHERE "report_id"=?';
}

sub select_report_record {
    return 'SELECT "id" FROM "report_record" WHERE "report_id"=? AND "source_ip"=? AND "count"=?'
}

sub select_todo_query {
    return <<'EO_TODO_QUERY'
SELECT "r"."id"    AS "rid",
    "r"."begin"    AS "begin",
    "r"."end"      AS "end",
    "a"."org_name" AS "author",
    "fd"."domain"  AS "from_domain"
FROM "report" "r"
LEFT JOIN "report_record" "rr" ON "r"."id"="rr"."report_id"
LEFT JOIN "author" "a"  ON "r"."author_id"="a"."id"
LEFT JOIN "domain" "fd" ON "r"."from_domain_id"="fd"."id"
WHERE "rr"."count" IS NULL
  AND "rr"."report_id" IS NOT NULL
  AND "r"."end" < ?
GROUP BY "r"."id", "r"."begin", "r"."end", "a"."org_name", "fd"."domain"
ORDER BY "r"."id" ASC
EO_TODO_QUERY
    ;
}

sub select_row_spf {
    return <<"EO_SPF_ROW"
SELECT "d"."domain" AS "domain",
       "s"."result" AS "result",
       "s"."scope"  AS "scope"
FROM "report_record_spf" "s"
LEFT JOIN "domain" "d" ON "s"."domain_id"="d"."id"
WHERE "s"."report_record_id"=?
ORDER BY "s"."id" ASC
EO_SPF_ROW
    ;
}


sub select_row_dkim {
    return <<"EO_DKIM_ROW"
SELECT "d"."domain"       AS "domain",
       "k"."selector"     AS "selector",
       "k"."result"       AS "result",
       "k"."human_result" AS "human_result"
FROM "report_record_dkim" "k"
LEFT JOIN "domain" "d" ON "k"."domain_id"="d"."id"
WHERE "report_record_id"=?
ORDER BY "k"."id" ASC
EO_DKIM_ROW
    ;
}

sub select_row_reason {
    return <<"EO_ROW_QUERY"
SELECT "type","comment"
FROM "report_record_reason"
WHERE "report_record_id"=?
EO_ROW_QUERY
    ;
}

sub select_rr_query {
    return <<'EO_ROW_QUERY'
SELECT "rr".*,
    "etd"."domain" AS "envelope_to",
    "efd"."domain" AS "envelope_from",
    "hfd"."domain" AS "header_from"
FROM "report_record" "rr"
LEFT JOIN "domain" "etd" ON "etd"."id"="rr"."envelope_to_did"
LEFT JOIN "domain" "efd" ON "efd"."id"="rr"."envelope_from_did"
LEFT JOIN "domain" "hfd" ON "hfd"."id"="rr"."header_from_did"
WHERE "report_id" = ?
ORDER BY "id" ASC
EO_ROW_QUERY
    ;
}

sub select_report_query {
    return <<'EO_REPORTS'
SELECT "r"."id"    AS "rid",
    "r"."uuid",
    "r"."begin"    AS "begin",
    "r"."end"      AS "end",
    "a"."org_name" AS "author",
    "fd"."domain"  AS "from_domain"
FROM "report" "r"
LEFT JOIN "author" "a"  ON "r"."author_id"="a"."id"
LEFT JOIN "domain" "fd" ON "r"."from_domain_id"="fd"."id"
WHERE 1=1
EO_REPORTS
    ;
}

sub insert_error {
    my ( $self, $which ) = @_;
    if ( $which == 0 ) {
        return 'UPDATE "report" SET "end"=? WHERE "id"=?';
    } else {
        return 'INSERT INTO "report_error" ("report_id", "error") VALUES (?,?)';
    }
}

sub insert_rr_reason {
    return 'INSERT INTO "report_record_reason" ("report_record_id", "type", "comment") VALUES (?,?,?)'
}

sub insert_rr_dkim {
    my ( $self, $fields ) = @_;
    my $fields_str = join '", "', @$fields;
    return <<"EO_DKIM"
INSERT INTO "report_record_dkim"
    ("report_record_id", \"$fields_str\")
VALUES (??)
EO_DKIM
    ;
}

sub insert_rr_spf {
    my ( $self, $fields ) = @_;
    my $fields_str = join '", "', @$fields;
    return "INSERT INTO \"report_record_spf\" (\"report_record_id\", \"$fields_str\") VALUES(??)";
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

sub select_from {
    my ($self, $columns, $table) = @_;
    my $colStr = '*';
    if ( @{$columns}[0] ne '*' ) {
        my @cols;
        foreach my $col (@$columns) {
            if ( $col =~ /(\w+)(?:\s+as\s+(\w+))/i ) {
                $col = "$1\" AS \"$2";
            }
            $col = "\"$col\"";
            push @cols, $col;
        }
        $colStr = join( ', ', @cols );
    }
    return "SELECT $colStr FROM \"$table\" WHERE 1=1";
}

sub insert_into {
    my ($self, $table, $cols) = @_;
    my $columns = '"' . join( '", "', @$cols ) . '"';
    return "INSERT INTO \"$table\" ($columns) VALUES (??)";
}

sub update {
    my ($self, $table, $cols) = @_;
    my $columns = '"' . join( '" = ?, "') . '" = ?';
    return "UPDATE \"$table\" SET $columns WHERE 1=1";
}

sub delete_from {
    my ($self, $table) = @_;
    return "DELETE FROM \"$table\" WHERE 1=1";
}

sub replace_into {
    my ($self, $table, $cols) = @_;
    my $insertColumns = '"' . join( '", "', @$cols ) . '"';
    my @ucols;
    foreach my $col (@$cols) {
        push @ucols, "\"$col\" = EXCLUDED.\"$col\""
    }
    my $updateColumns = join ', ', @ucols;
    return "INSERT INTO \"$table\" ($insertColumns) VALUES (??)
        ON CONFLICT ($insertColumns) DO UPDATE SET $updateColumns";
}

1;

# ABSTRACT: Grammar for working with pgsql databases.
__END__

=head1 SYPNOSIS

Allow DMARC to be able to speak to PostgreSQL databases.

=head1 DESCRIPTION

Uses ANSI SQL syntax, keeping the SQL as portable as possible.

DB engine specific features are to be avoided.

=cut