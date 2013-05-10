package Mail::DMARC::Report::Store::SQL;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use DBIx::Simple;
use Net::IP;

use parent 'Mail::DMARC::Base';

sub save {
    my $self = shift;
    $self->{dmarc} = shift or croak "missing object with DMARC results\n";
    my $too_many = shift and croak "invalid arguments";

    $self->insert_report or croak "failed to create report!";
    $self->insert_report_row or croak "failed to insert row";
    $self->insert_rr_reason;  # optional
    $self->insert_rr_spf;     # optional
    $self->insert_rr_dkim;    # optional, multiple possible

#warn Dumper($self->{dmarc});
    return $self->{report_row_id};
};

sub dmarc { return $_[0]->{dmarc}; };

sub retrieve {
    my $self = shift;
    my $reports = $self->query( 'SELECT * FROM report' );
#    my $last = $reports->[-1];
#my $details = $self->query( 'SELECT * FROM report r' );
    return $reports;
};

sub insert_rr_reason {
    my $self = shift;
    my $type = $self->dmarc->result->evaluated->reason->type or do {
        return 1;
    };
    my $comment = $self->dmarc->result->evaluated->reason->comment || '';
    return $self->query( 'INSERT INTO report_record_disp_reason (report_record_id, type, comment) VALUES (?,?,?)',
            [ $self->{report_row_id}, $type, $comment ]
        );
};

sub insert_rr_dkim {
    my $self = shift;
    my $dkim = $self->dmarc->dkim or do {
        carp "no DKIM results!\n";
        return;
    };
    foreach my $sig ( @$dkim ) {
    $self->query(
'INSERT INTO report_record_dkim (report_record_id, domain, selector, result, human_result) VALUES (?,?,?,?,?)',
            [ $self->{report_row_id}, $sig->{domain}, $sig->{selector}, $sig->{result}, $sig->{human_result} ]
        );
    };
    return 1;
};

sub insert_rr_spf {
    my $self = shift;
    my $spf = $self->dmarc->spf or do {
        warn "no SPF results!\n";
        return;
    };
#warn Dumper($spf);
    my $r = $self->query(
'INSERT INTO report_record_spf (report_record_id, domain, scope, result) VALUES(?,?,?,?)',
            [
            $self->{report_row_id},
            $spf->{domain},
            $spf->{scope},
            $spf->{result},
            ]
        ) or croak "failed to insert SPF";

    return $r;
};

sub insert_report_row {
    my $self = shift;
    my $report_id = $self->{report_id} or croak "no report_id?!";
    my $eva = $self->dmarc->result->evaluated or croak "no evaluated report?!";
# using SQL SET rather than INSERT won't break when the table schema changes
    my $query = <<'EO_ROW_INSERT'
INSERT INTO report_record (report_id, source_ip, disposition,
    dkim, spf, header_from, envelope_to, envelope_from ) VALUES (?,?,?,?,?,?,?,?)
EO_ROW_INSERT
;
    my $args = [
        $self->{report_id},
        Net::IP->new($self->dmarc->source_ip)->intip,
        $eva->disposition,
        $eva->dkim,
        $eva->spf,
        $self->dmarc->header_from,
        $self->dmarc->envelope_to || '',
        $self->dmarc->envelope_from || '',
        ];

    my $row_id = $self->query( $query, $args )
        or croak "query failed: $query\n";
#warn "row_id: $row_id\n";
    return $self->{report_row_id} = $row_id;
};

sub insert_report {
    my $self = shift;

    my $header_from = $self->dmarc->header_from or croak "missing header_from!";
    my $ids = $self->query(
        'SELECT id FROM report WHERE domain=? AND end > ?',
        [ $header_from, time ]
        );

    if ( scalar @$ids ) {
#       warn "found " . scalar @$ids . " matching reports!";
        return $self->{report_id} = $ids->[0]{id};
    }

# if a report for author_domain does not exist, insert new report
    $self->{report_id} = $self->query(
        'INSERT INTO report (domain, begin, end) VALUES (?, ?, ?)',
        [
        $header_from, time,
        time + ($self->dmarc->result->published->ri || 86400),
        ]
    );

    $self->insert_report_published_policy();
    return $self->{report_id};
};

sub insert_report_published_policy {
    my $self = shift;
    my $pub = $self->dmarc->result->published;
    $pub->apply_defaults;
    my $query = 'INSERT INTO report_policy_published (report_id, adkim, aspf, p, sp, pct) VALUES (?,?,?,?,?,?)';
    return $self->query( $query, [
            $self->{report_id},
            $pub->adkim,
            $pub->aspf,
            $pub->p,
            $pub->sp,
            $pub->pct,
            ]
            ) or croak "failed to insert published policy";
};

sub db_connect {
    my ($self, $config) = @_;

    return $self->{dbh} if $self->{dbh};   # caching

    my $dsn  = $self->config->{report_store}{dsn} or croak;
    my $user = $self->config->{report_store}{user};
    my $pass = $self->config->{report_store}{pass};

    if ( $dsn =~ /sqlite/i ) {
        my ($file) = (split /=/, $dsn)[-1];
        if ( ! $file || ! -e $file ) {
            if ( -f 'sql/mail_dmarc.sqlite' ) {
                system "sqlite3 $file < sql/mail_dmarc.sqlite";
            }
            else {
                croak "no such DB file $file!\n";
            };
        };
    };

    $self->{dbh} = DBIx::Simple->connect( $dsn, $user, $pass )
        or return $self->error( DBIx::Simple->error );

    return $self->{dbh};
};

sub query {
    my ( $self, $query, $params, @extra ) = @_;

    my @c = caller;
    my $err = sprintf( "query called by %s, %s\n", $c[0], $c[2] )
            . "\t$query\n\t";

    my @params;
    if ( defined $params ) {
        @params = ref $params eq 'ARRAY' ? @$params : $params;
        no warnings;  ## no critic (NoWarnings)
        $err .= join( ', ', @params );
    }

    croak "too many arguments to exec_query!" if @extra;

    my $dbix = $self->db_connect() or croak DBIx::Simple->error;

    return $self->query_insert( $query, $err, @params) if $query =~ /^INSERT/ix;
    return $self->query_replace($query, $err, @params) if $query =~ /^REPLACE/ix;
    return $self->query_update( $query, $err, @params) if $query =~ /^UPDATE/ix;
    return $self->query_delete( $query, $err, @params) if $query =~ /^DELETE/ix;
    return $self->query_any($query, $err, @params);
};

sub query_any {
    my ($self, $query, $err, @params) = @_;
    my $dbix = $self->{dbh} or croak "no DB handle";
    my $r;
    eval { $r = $dbix->query( $query, @params )->hashes } or do {
        carp $err . $dbix->error if $dbix->error ne 'DBI error: ';
    };
    carp "$err\n$@\n" if $@;
    return $r;
};

sub query_insert {
    my ($self, $query, $err, @params) = @_;
    my $dbix = $self->{dbh};
    my (undef,undef,$table) = split /\s+/, $query;
    ($table) = split( /\(/, $table) if $table =~ /\(/; 
    eval { $dbix->query( $query, @params ); } or do {
        carp $dbix->error if $dbix->error ne 'DBI error: ';
    };
    if ( $@ ) { carp "$@\n$err"; return; };
    # If the table has no autoincrement field, last_id is zero
    return $dbix->last_insert_id( undef, undef, $table, undef );
};

sub query_replace {
    my ($self, $query, $err, @params) = @_;
    my $dbix = $self->{dbh};
    eval { $dbix->query( $query, @params ) } or do {
        carp $dbix->error if $dbix->error ne 'DBI error: ';
        return;
    };
    if ( $@ ) { carp "$@\n$err"; return; };
    return 1;  # sorry, no indication of success
};

sub query_update {
    my ($self, $query, $err, @params) = @_;
    my $dbix = $self->{dbh};
    eval { $dbix->query( $query, @params ) } or do {
        carp $dbix->error if $dbix->error ne 'DBI error: ';
        return;
    };
    if ( $@ ) { carp "$@\n$err"; return; };
    return 1;
};

sub query_delete {
    my ($self, $query, $err, @params) = @_;
    my $dbix = $self->{dbh};
    $dbix->query( $query, @params ) or do {
        carp $err . $dbix->error if $dbix->error ne 'DBI error: ';
        return;
    };
    my $affected = 0;
    eval { $affected = $dbix->query("SELECT ROW_COUNT()")->list }; ## no critic (Eval)
    return 1 if $@;  # succeed for SQLite
    return $affected;
};


1;
# ABSTRACT: Store DMARC reports
__END__

=head1 SYPNOSIS

Retreive DMARC reports from SQL data store

=head1 DESCRIPTION

Using ANSI SQL syntax, so the resulting SQL is as portable as possible.

Working and tested with SQLite and MySQL.

=cut
