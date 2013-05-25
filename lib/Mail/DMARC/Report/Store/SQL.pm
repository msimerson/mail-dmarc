package Mail::DMARC::Report::Store::SQL;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use DBIx::Simple;
use File::ShareDir;

use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Aggregate;

sub save_aggregate {
    my ( $self, $agg ) = @_;

    croak "policy_published must be a Mail::DMARC::Policy object"
        if 'Mail::DMARC::Policy' ne ref $agg->policy_published;

    #warn Dumper($meta); ## no critic (Carp)
    foreach my $f ( qw/ domain org_name email begin end / ) {
        croak "meta field $f required" if ! $agg->metadata->$f;
    }

    my $rid = $self->get_aggregate_rid( $agg )
        or croak "failed to create report!";

    foreach my $rec ( @{ $agg->record } ) {
        next if !$rec;
        $self->insert_aggregate_row($rid, $rec);
    };

    return $rid;
};

sub retrieve {
    my ( $self, %args ) = @_;

    my $query = $self->get_report_query;
    my @params;
    my @known = qw/ rid author rcpt_domain from_domain begin end /;

    foreach my $known ( @known ) {
        next if ! defined $args{$known};
        $query .= " AND $known=?";
        push @params, $args{$known};
    };
    my $reports = $self->query( $query );

    foreach (@$reports ) {
        $_->{begin} = join(" ", split(/T/, $self->epoch_to_iso( $_->{begin} )));
        $_->{end} = join(" ", split(/T/, $self->epoch_to_iso( $_->{end} )));
    };
    return $reports;
}

sub retrieve_todo {
    my ( $self, %args ) = @_;

#carp "author id: $author_id\n";
    my $reports = $self->query( 'SELECT * FROM report r LEFT JOIN report_record rr ON r.id=rr.report_id WHERE rr.count IS NULL AND r.end < ? LIMIT 1', [ time ] );
    return if ! @$reports;
    my $report = $reports->[0];
carp "report: " . Dumper($report);

    my $agg = Mail::DMARC::Report::Aggregate->new();
    $agg->metadata->report_id( $report->{id} );

    foreach my $f ( qw/ domain org_name email extra_contact_info / ) {
        $agg->metadata->$f( $self->config->{organization}{$f} );
    };
    foreach my $f ( qw/ begin end / ) {
        $agg->metadata->$f( $report->{$f} );
    };

    my $errors = $self->query('SELECT error FROM report_error WHERE report_id=?', [ $report->{id} ] );
    foreach ( @$errors ) {
        $agg->metadata->error( $_->{error} );
    };

    my $pp = $self->query(
            'SELECT * from report_policy_published WHERE report_id=?',
            [ $report->{id} ]
            )->[0];
    $pp->{v} = 'DMARC1';
    $pp->{p} ||= 'none';
    $agg->policy_published( Mail::DMARC::Policy->new( %$pp ) );
#carp "aggregate: " . Dumper($agg);

    my $rows = $self->query( 'SELECT * from report_record WHERE report_id=?',
        [ $report->{id} ] );

    foreach my $row (@$rows) {
        $row->{source_ip} = $self->any_inet_ntop( $row->{source_ip} );
        $row->{reason}    = $self->query(
            'SELECT type,comment from report_record_reason WHERE report_record_id=?',
            [ $row->{id} ]
        );
        $row->{auth_results}{spf} = $self->query(
            'SELECT domain,result,scope from report_record_spf WHERE report_record_id=?',
            [ $row->{id} ]
        );
        $row->{auth_results}{dkim} = $self->query(
            'SELECT domain,selector,result,human_result from report_record_dkim WHERE report_record_id=?',
            [ $row->{id} ]
        );
        $agg->record($row);
    }
    return $agg;
}

sub delete_report {
    my $self = shift;
    my $report_id = shift or carp "missing report ID";
    print "deleting report $report_id\n";

    # deletes with FK don't cascade in SQLite? Clean each table manually
    my $rows = $self->query( 'SELECT id FROM report_record WHERE report_id=?',
        [$report_id] );
    my $row_ids = join( ',', map { $_->{id} } @$rows ) or return 1;
    foreach my $table (
        qw/ report_record_spf report_record_dkim report_record_reason /)
    {
        print "deleting $table rows $row_ids\n";
        $self->query(
            "DELETE FROM $table WHERE report_record_id IN ($row_ids)");
    }
    foreach my $table (qw/ report_policy_published report_record /) {
        $self->query( "DELETE FROM $table WHERE report_id=?", [$report_id] );
    }

    # In MySQL, where FK constraints DO cascade, this is the only query needed
    $self->query( "DELETE FROM report WHERE id=?", [$report_id] );
    return 1;
}

sub get_domain_id {
    my ( $self, $domain ) = @_;
    croak "missing domain calling " . ( caller(0) )[3] if !$domain;
    my $r = $self->query( 'SELECT id FROM domain WHERE domain=?', [$domain] );
    if ( $r && scalar @$r ) {
        return $r->[0]{id};
    }
    return $self->query( 'INSERT INTO domain (domain) VALUES (?)',
        [$domain] );
}

sub get_author_id {
    my ( $self, $meta ) = @_;
    croak "missing author name" if !$meta->org_name;
    my $r = $self->query( 'SELECT id FROM author WHERE org_name=?',
        [ $meta->org_name ] );
    if ( $r && scalar @$r ) {
        return $r->[0]{id};
    }
    carp "missing email" if !$meta->email;
    return $self->query(
        'INSERT INTO author (org_name,email,extra_contact) VALUES (??)',
        [ $meta->org_name, $meta->email, $meta->extra_contact_info ]
    );
}

sub get_aggregate_rid {
    my ( $self, $aggregate ) = @_;

    my $meta = $aggregate->metadata;
    my $pol  = $aggregate->policy_published;

    # check if report exists
    my $rcpt_dom_id = $self->get_domain_id( $meta->domain );
    my $author_id   = $self->get_author_id( $meta );
    my $from_dom_id = $self->get_domain_id( $pol->domain );

    my $ids;
    if ( $meta->report_id ) {
# aggregate reports arriving via the wire will have a report ID
        $ids = $self->query(
        'SELECT id FROM report WHERE rcpt_domain_id=? AND uuid=? AND author_id=?',
        [ $rcpt_dom_id, $meta->report_id, $author_id ]
        );
    }
    else {
# reports submitted by our local MTA will not have a report ID
        $ids = $self->query(
        'SELECT id FROM report WHERE rcpt_domain_id=? AND author_id=? AND end > ?',
        [ $rcpt_dom_id, $author_id, time ]
        );
    };

    if ( scalar @$ids ) { # report already exists
        return $self->{report_id} = $ids->[0]{id};
    }

    my $rid = $self->{report_id} = $self->query(
        'INSERT INTO report (from_domain_id, rcpt_domain_id, begin, end, author_id, uuid) VALUES (??)',
        [ $from_dom_id, $rcpt_dom_id, $meta->begin, $meta->end, $author_id, $meta->uuid ]
    ) or return;

    $self->insert_published_policy( $rid, $pol );
    return $rid;
}

sub get_report {
    my ($self,@args) = @_;
    croak "invalid parameters" if @args % 2;
    my %args = @args;
#warn Dumper(\%args);

    my $query = $self->get_report_query;
    my @params;
    my @known = qw/ rid author rcpt_domain from_domain begin end /;
    my %known = map { $_ => 1 } @known;

# TODO: allow custom search ops?  'searchOper'   => 'eq',
    if ( $args{searchField} && $known{ $args{searchField} } ) {
        $query .= " AND $args{searchField}=?";
        push @params, $args{searchString};
    };

    foreach my $known ( @known ) {
        next if ! defined $args{$known};
        $query .= " AND $known=?";
        push @params, $args{$known};
    };
    if ( $args{sidx} && $known{$args{sidx}} ) {
        $query .= " ORDER BY " . $args{sidx};
        if ( $args{sord} ) {
            $query .= $args{sord} eq 'desc' ? ' DESC' : ' ASC';
        };
    };
    my $total_recs = $self->dbix->query('SELECT COUNT(*) FROM report')->list;
    my $total_pages = 0;
    if ( $args{rows} ) {
        if ( $args{page} ) {
            $total_pages = POSIX::ceil($total_recs / $args{rows});
            my $start = ($args{rows} * $args{page}) - $args{rows};
            $start = 0 if $start < 0;
            $query .= " LIMIT ?,?";
            push @params, $start, $args{rows};
        }
        else {
            $query .= " LIMIT ?";
            push @params, $args{rows};
        };
    };

#   warn "query: $query\n" . join(", ", @params) . "\n";
    my $reports = $self->query($query, \@params);
    foreach (@$reports ) {
        $_->{begin} = join('<br>', split(/T/, $self->epoch_to_iso( $_->{begin} )));
        $_->{end} = join('<br>', split(/T/, $self->epoch_to_iso( $_->{end} )));
    };
# return in the format expected by jgGrid
    return {
        cur_page    => $args{page},
        total_pages => $total_pages,
        total_rows  => $total_recs,
        rows        => $reports,
    };
};

sub get_report_query {
    my $self = shift;
    return <<'EO_REPORTS'
SELECT r.id    AS rid,
    r.uuid,
    r.begin    AS begin,
    r.end      AS end,
    a.org_name AS author,
    rd.domain  AS rcpt_domain,
    fd.domain  AS from_domain
FROM report r
LEFT JOIN author a  ON r.author_id=a.id
LEFT JOIN domain rd ON r.rcpt_domain_id=rd.id
LEFT JOIN domain fd ON r.from_domain_id=fd.id
WHERE 1=1
EO_REPORTS
;
};

sub get_row {
    my ($self,@args) = @_;
    croak "invalid parameters" if @args % 2;
    my %args = @args;
#warn Dumper(\%args);
    croak "missing report ID (rid)!" if ! defined $args{rid};

    my $query = 'SELECT * FROM report_record WHERE report_id = ?';
    my @params = $args{rid};

    my $rows = $self->query($query, \@params);
    foreach ( @$rows ) {
        $_->{reasons} = $self->query('SELECT type,comment FROM report_record_reason WHERE report_record_id=?', [ $_->{id} ] );
        $_->{source_ip} = $self->any_inet_ntop( $_->{source_ip} );
    };
    return {
        cur_page    => 1,
        total_pages => 1,
        total_rows  => scalar @$rows,
        rows        => $rows,
    };
};

sub row_exists {
    my ($self, $rid, $rec ) = @_;

    if ( ! defined $rec->{count} ) {
        carp "\tnew record";
        return;
    };

    my $rows = $self->query('SELECT id FROM report_record WHERE report_id=? AND source_ip=? AND count=?',
            [ $rid, $rec->{identifiers}{source_ip}, $rec->{count}, ]
            );

    return 1 if scalar @$rows;
    return;
};

sub insert_aggregate_row {
    my ($self, $rid, $rec) = @_;

    return 1 if $self->row_exists( $rid, $rec);

    my @idfs = qw/ source_ip header_from envelope_to envelope_from /;
    my @evfs = qw/ disposition dkim spf /;
    my $row_id = $self->insert_rr( $rid, $rec )
        or croak "failed to insert report row";

    my $reasons = $rec->{policy_evaluated}{reason};
    if ( $reasons ) {
        foreach my $reason ( @$reasons ) {
            next if ! $reason || ! $reason->{type};
            $self->insert_rr_reason( $row_id, $reason->{type},
                $reason->{comment} );
        };
    }

    my $spf_ref = $rec->{auth_results}{spf};
    if ( $spf_ref ) {
        foreach my $spf (@$spf_ref) {
            $self->insert_rr_spf( $row_id, $spf );
        }
    }

    my $dkim = $rec->{auth_results}{dkim};
    if ($dkim) {
        foreach my $sig (@$dkim) {
            next if ! $sig || ! $sig->{domain};
            $self->insert_rr_dkim( $row_id, $sig );
        }
    }
    return 1;
}

sub insert_rr_reason {
    my ( $self, $row_id, $type, $comment ) = @_;
    return $self->query(
        'INSERT INTO report_record_reason (report_record_id, type, comment) VALUES (?,?,?)',
        [ $row_id, $type, $comment || '' ]
    );
}

sub insert_rr_dkim {
    my ( $self, $row_id, $dkim ) = @_;

    my $query = <<'EO_DKIM'
INSERT INTO report_record_dkim
    (report_record_id, domain, selector, result, human_result)
VALUES (??)
EO_DKIM
        ;
    my @dkim_fields = qw/ domain selector result human_result /;
    $self->query( $query, [ $row_id, map { $dkim->{$_} } @dkim_fields ] );
    return 1;
}

sub insert_rr_spf {
    my ( $self, $row_id, $spf ) = @_;
    my $r = $self->query(
        'INSERT INTO report_record_spf (report_record_id, domain, scope, result) VALUES(??)',
        [ $row_id, $spf->{domain}, $spf->{scope}, $spf->{result}, ]
    ) or croak "failed to insert SPF";
    return $r;
}

sub insert_rr {
    my ( $self, $report_id, $row ) = @_;
    $report_id or croak "report ID required?!";
    my $query = <<'EO_ROW_INSERT'
INSERT INTO report_record
   (report_id, source_ip, count, header_from, envelope_to, envelope_from,
    disposition, dkim, spf
    )
   VALUES (??)
EO_ROW_INSERT
        ;

    my @idfs = qw/ header_from envelope_to envelope_from /;
    my @evfs = qw/ disposition dkim spf /;
    my $args = [
        $report_id,
        $self->any_inet_pton( $row->{identifiers}{source_ip} ),
        $row->{count},
        ( map { $row->{identifiers}{$_} || '' } @idfs ),
        ( map { $row->{policy_evaluated}{$_} } @evfs ),
    ];
    my $row_id = $self->query( $query, $args ) or croak;
    return $self->{report_row_id} = $row_id;
}

sub insert_published_policy {
    my ( $self, $id, $pub ) = @_;
    my $query
        = 'INSERT INTO report_policy_published (report_id, adkim, aspf, p, sp, pct, rua) VALUES (??)';
    return $self->query(
        $query,
        [   $id,        $pub->{adkim}, $pub->{aspf}, $pub->{p},
            $pub->{sp}, $pub->{pct},   $pub->{rua},
        ]
    ) or croak "failed to insert published policy";
}

sub db_connect {
    my $self = shift;

    return $self->{dbix} if $self->{dbix};    # caching

    my $dsn  = $self->config->{report_store}{dsn} or croak;
    my $user = $self->config->{report_store}{user};
    my $pass = $self->config->{report_store}{pass};

    my $needs_tables;
    if ( $dsn =~ /sqlite/i ) {
        my ($db) = ( split /=/, $dsn )[-1];
        if ( !$db || $db eq ':memory:' || !-e $db ) {
            my $schema = 'mail_dmarc_schema.sqlite';
            $needs_tables = $self->get_db_schema($schema)
                or croak
                "can't locate DB $db AND can't find $schema! Create $db manually.\n";
        }
    }

    $self->{dbix} = DBIx::Simple->connect( $dsn, $user, $pass )
        or return $self->error( DBIx::Simple->error );

    if ($needs_tables) {
        $self->apply_db_schema($needs_tables);
    }
    return $self->{dbix};
}

sub db_check_err {
    my ( $self, $err ) = @_;
    ## no critic (PackageVars)
    return if !defined $DBI::errstr;
    return if !$DBI::errstr;
    return if $DBI::errstr eq 'DBI error: ';
    croak $err . $DBI::errstr;
}

sub dbix { return $_[0]->{dbix} if $_[0]->{dbix}; return $_[0]->db_connect(); }

sub apply_db_schema {
    my ( $self, $file ) = @_;
    my $setup = $self->slurp($file);
    foreach ( split /;/, $setup ) {
#       warn "$_\n";
        $self->dbix->query($_);
    }
    return;
}

sub get_db_schema {
    my ( $self, $file ) = @_;
    return "share/$file" if -f "share/$file";    # when testing
    return File::ShareDir::dist_file( 'Mail-DMARC', $file );  # when installed
}

sub query {
    my ( $self, $query, $params, @extra ) = @_;

    my @c = caller;
    my $err = sprintf( "query called by %s, %s\n", $c[0], $c[2] )
        . "\t$query\n\t";

    my @params;
    if ( defined $params ) {
        @params = ref $params eq 'ARRAY' ? @$params : $params;
        no warnings;    ## no critic (NoWarnings)
        $err .= join( ', ', @params );
    }

    croak "too many arguments to exec_query!" if @extra;

    my $dbix = $self->db_connect() or croak DBIx::Simple->error;

    return $self->query_insert( $query, $err, @params )
        if $query =~ /^INSERT/ix;
    return $self->query_replace( $query, $err, @params )
        if $query =~ /^REPLACE/ix;
    return $self->query_update( $query, $err, @params )
        if $query =~ /^UPDATE/ix;
    return $self->query_delete( $query, $err, @params )
        if $query =~ /^DELETE/ix;
    return $self->query_any( $query, $err, @params );
}

sub query_any {
    my ( $self, $query, $err, @params ) = @_;
#warn "query: $query\n" . join(", ", @params) . "\n";
    my $r = $self->dbix->query( $query, @params )->hashes or croak $err;
    $self->db_check_err($err);
    return $r;
}

sub query_insert {
    my ( $self, $query, $err, @params ) = @_;
    $self->dbix->query( $query, @params ) or croak $err;
    $self->db_check_err($err);

    # If the table has no autoincrement field, last_insert_id is zero
    my ( undef, undef, $table ) = split /\s+/, $query;
    ($table) = split( /\(/, $table ) if $table =~ /\(/;
    croak "unable to determine table in query: $query" if !$table;
    return $self->dbix->last_insert_id( undef, undef, $table, undef );
}

sub query_replace {
    my ( $self, $query, $err, @params ) = @_;
    $self->dbix->query( $query, @params ) or croak $err;
    $self->db_check_err($err);
    return 1;    # sorry, no indication of success
}

sub query_update {
    my ( $self, $query, $err, @params ) = @_;
    $self->dbix->query( $query, @params ) or croak $err;
    $self->db_check_err($err);
    return 1;
}

sub query_delete {
    my ( $self, $query, $err, @params ) = @_;
    $self->dbix->query( $query, @params ) or croak $err;
    $self->db_check_err($err);
    my $affected = 0;
    eval { $affected = $self->dbix->query("SELECT ROW_COUNT()")->list }; ## no critic (Eval)
    return 1 if $@;    # succeed for SQLite
    return $affected;
}

1;

# ABSTRACT: SQL storage for DMARC reports
__END__

=head1 SYPNOSIS

Store and retrieve DMARC reports from SQL data store.

=head1 DESCRIPTION

Using ANSI SQL syntax, so the resulting SQL is as portable as possible.

Working and tested with SQLite and MySQL.

=cut
