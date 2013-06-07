package Mail::DMARC::Report::Store::SQL;
# VERSION
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
    foreach my $f ( qw/ org_name email begin end / ) {
        croak "meta field $f required" if ! $agg->metadata->$f;
    }

    my $rid = $self->get_report_id( $agg )
        or croak "failed to create report!";

    foreach my $rec ( @{ $agg->record } ) {
        $self->insert_agg_record($rid, $rec);
    };

    return $rid;
};

sub retrieve {
    my ( $self, %args ) = @_;

    my $query = $self->get_report_query;
    my @params;
    my @known = qw/ rid author from_domain begin end /;

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
    my ( $self, @args ) = @_;

# this method extracts the data from the SQL tables and populates an
# Aggregate report object with it.
    my $reports = $self->query( $self->get_todo_query, [ time ] );
    return if ! @$reports;
    my $report = $reports->[0];

    my $agg = Mail::DMARC::Report::Aggregate->new();
    $self->populate_agg_metadata( \$agg, \$report );

    my $pp = $self->get_report_policy_published( $report->{rid} );
    $pp->{domain} = $report->{from_domain};
    $agg->policy_published( Mail::DMARC::Policy->new( %$pp ) );

    $self->populate_agg_records( \$agg, $report->{rid} );
    return $agg;
};

sub delete_report {
    my $self = shift;
    my $report_id = shift or croak "missing report ID";
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
    return $self->query( 'INSERT INTO domain (domain) VALUES (?)', [$domain]);
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

sub get_report_id {
    my ( $self, $aggr ) = @_;

    my $meta = $aggr->metadata;
    my $pol  = $aggr->policy_published;

    # check if report exists
    my $author_id   = $self->get_author_id( $meta )         or croak;
    my $from_dom_id = $self->get_domain_id( $pol->domain )  or croak;

    my $ids;
    if ( $meta->report_id ) {
# reports arriving via the wire will have an author ID & report ID
        $ids = $self->query(
        'SELECT id FROM report WHERE uuid=? AND author_id=?',
        [ $meta->report_id, $author_id ]
        );
    }
    else {
# Reports submitted by our local MTA will not have a report ID
# They aggregate on the From domain, where the DMARC policy was discovered
        $ids = $self->query(
        'SELECT id FROM report WHERE from_domain_id=? AND end > ?',
        [ $from_dom_id, time ]
        );
    };

    if ( scalar @$ids ) { # report already exists
        return $self->{report_id} = $ids->[0]{id};
    }

    my $rid = $self->{report_id} = $self->query(
        'INSERT INTO report (from_domain_id, begin, end, author_id, uuid) VALUES (??)',
        [ $from_dom_id, $meta->begin, $meta->end, $author_id, $meta->uuid ]
    ) or return;

    $self->insert_policy_published( $rid, $pol );
    return $rid;
}

sub get_report {
    my ($self,@args) = @_;
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my $query = $self->get_report_query;
    my @params;
    my @known = qw/ rid author from_domain begin end /;
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
# return in the format expected by jqGrid
    return {
        cur_page    => $args{page},
        total_pages => $total_pages,
        total_rows  => $total_recs,
        rows        => $reports,
    };
};

sub get_report_policy_published {
    my ($self, $rid) = @_;
    my $pp_query = 'SELECT * from report_policy_published WHERE report_id=?';
    my $pp = $self->query($pp_query, [ $rid ] )->[0];
    $pp->{p} ||= 'none';
    $pp = Mail::DMARC::Policy->new( v=>'DMARC1', %$pp );
    return $pp;
};

sub get_report_query {
    my $self = shift;
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
};

sub get_todo_query {
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
GROUP BY rid
ORDER BY rid
LIMIT 1
EO_TODO_QUERY
;
};

sub get_rr {
    my ($self,@args) = @_;
    croak "invalid parameters" if @args % 2;
    my %args = @args;
#warn Dumper(\%args);
    croak "missing report ID (rid)!" if ! defined $args{rid};

    my $rows = $self->query( $self->get_rr_query, [ $args{rid} ] );
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

sub get_row_spf {
    my ($self, $rowid) = @_;

    my $spf_query = <<"EO_SPF_ROW"
SELECT d.domain AS domain,
       s.result AS result,
       s.scope  AS scope
FROM report_record_spf s
LEFT JOIN domain d ON s.domain_id=d.id
WHERE s.report_record_id=?
EO_SPF_ROW
;
    return $self->query( $spf_query, [ $rowid ] );
};

sub get_row_dkim {
    my ($self, $rowid) = @_;

    my $dkim_query = <<"EO_DKIM_ROW"
SELECT d.domain       AS domain,
       k.selector     AS selector,
       k.result       AS result,
       k.human_result AS human_result
FROM report_record_dkim k
LEFT JOIN domain d ON k.domain_id=d.id
WHERE report_record_id=?
EO_DKIM_ROW
;
    return $self->query( $dkim_query, [ $rowid ] );
};

sub get_row_reason {
    my ($self, $rowid) = @_;
    my $row_query = <<"EO_ROW_QUERY"
SELECT type,comment
FROM report_record_reason
WHERE report_record_id=?
EO_ROW_QUERY
    ;
    return $self->query( $row_query, [ $rowid ] );
};

sub get_rr_query {
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
ORDER BY id
EO_ROW_QUERY
        ;
};

sub populate_agg_metadata {
    my ($self, $agg_ref, $report_ref) = @_;

    $$agg_ref->metadata->report_id( $$report_ref->{rid} );

    foreach my $f ( qw/ org_name email extra_contact_info / ) {
        $$agg_ref->metadata->$f( $self->config->{organization}{$f} );
    };
    foreach my $f ( qw/ begin end / ) {
        $$agg_ref->metadata->$f( $$report_ref->{$f} );
    };

    my $errors = $self->query('SELECT error FROM report_error WHERE report_id=?',
            [ $$report_ref->{rid} ]
        );
    foreach ( @$errors ) {
        $agg_ref->metadata->error( $_->{error} );
    };
    return 1;
};

sub populate_agg_records {
    my ($self, $agg_ref, $rid) = @_;

    my $recs = $self->query( $self->get_rr_query, [ $rid ] );

    # aggregate the connections per IP-Disposition-DKIM-SPF uniqueness
    my (%ips, %uniq, %pe, %auth, %ident, %reasons);
    foreach my $rec ( @$recs ) {
        my $key = join('-', $rec->{source_ip},
                @$rec{ qw/ disposition dkim spf / }); # hash slice
        $uniq{ $key }++;
        $ips{$key} = $rec->{source_ip};
        $ident{$key}{header_from}   ||= $rec->{header_from};
        $ident{$key}{envelope_from} ||= $rec->{envelope_from};
        $ident{$key}{envelope_to}   ||= $rec->{envelope_to};

        $pe{$key}{disposition} ||= $rec->{disposition};
        $pe{$key}{dkim}   ||= $rec->{dkim};
        $pe{$key}{spf}    ||= $rec->{spf};

        $auth{$key}{spf } ||= $self->get_row_spf($rec->{id});
        $auth{$key}{dkim} ||= $self->get_row_dkim($rec->{id});

        my $reasons = $self->get_row_reason( $rec->{id} );
        foreach my $reason ( @$reasons ) {
            my $type = $reason->{type} or next;
            $reasons{$key}{$type} = $reason->{comment};   # flatten reasons
        }
    }

    foreach my $u ( keys %uniq ) {
        $$agg_ref->record( {
            identifiers  => $ident{$u},
            auth_results => $auth{$u},
            row => {
                source_ip => $self->any_inet_ntop( $ips{$u} ),
                count     => $uniq{ $u },
                policy_evaluated => {
                    %{ $pe{$u} },
                    $reasons{$u} ? ( reason => [ map { { type => $_, comment => $reasons{$u}{$_} } } sort keys %{ $reasons{$u} } ] ) : (),
                },
            },
        } );
    }
    return $$agg_ref->record;
}

sub row_exists {
    my ($self, $rid, $rec ) = @_;

    if ( ! defined $rec->{row}{count} ) {
        carp "\tnew record";
        return;
    };

    my $rows = $self->query('SELECT id FROM report_record WHERE report_id=? AND source_ip=? AND count=?',
            [ $rid, $rec->{row}{source_ip}, $rec->{row}{count}, ]
            );

    return 1 if scalar @$rows;
    return;
};

sub insert_agg_record {
    my ($self, $rid, $rec) = @_;

    return 1 if $self->row_exists( $rid, $rec);

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
    my (@fields, @values);
    foreach ( qw/ domain selector result human_result / ) {
        next if ! $dkim->{$_};
        if ( 'domain' eq $_ ) {
            push @fields, 'domain_id';
            push @values, $self->get_domain_id( $dkim->{domain} );
            next;
        };
        push @fields, $_;
        push @values, $dkim->{$_};
    };
    my $fields_str = join ',', @fields;
    my $query = <<"EO_DKIM"
INSERT INTO report_record_dkim
    (report_record_id, $fields_str)
VALUES (??)
EO_DKIM
        ;
    $self->query( $query, [ $row_id, @values ] );
    return 1;
}

sub insert_rr_spf {
    my ( $self, $row_id, $spf ) = @_;
    my (@fields, @values);
    for ( qw/ domain scope result / ) {
        next if ! $spf->{$_};
        if ( 'domain' eq $_ ) {
            push @fields, 'domain_id';
            push @values, $self->get_domain_id( $spf->{domain} );
            next;
        };
        push @fields, $_;
        push @values, $spf->{$_};
    };
    my $fields_str = join ',', @fields;
    my $query = "INSERT INTO report_record_spf (report_record_id, $fields_str) VALUES(??)";
    $self->query( $query, [ $row_id, @values ]);
    return 1;
}

sub insert_rr {
    my ( $self, $report_id, $rec ) = @_;
    $report_id or croak "report ID required?!";
    my $query = <<'EO_ROW_INSERT'
INSERT INTO report_record
   (report_id, source_ip, count, header_from_did, envelope_to_did, envelope_from_did,
    disposition, dkim, spf)
   VALUES (??)
EO_ROW_INSERT
        ;

    my @args = ( $report_id,
        $self->any_inet_pton( $rec->{row}{source_ip} ),
        $rec->{row}{count},
    );
    foreach ( qw/ header_from envelope_to envelope_from / ) {
        push @args, $rec->{identifiers}{$_} ?
            $self->get_domain_id( $rec->{identifiers}{$_} ) : undef;
    };
    push @args, map { $rec->{row}{policy_evaluated}{$_} } qw/ disposition dkim spf /;
    my $rr_id = $self->query( $query, \@args ) or croak;
    return $self->{report_row_id} = $rr_id;
}

sub insert_policy_published {
    my ( $self, $id, $pub ) = @_;
    my $query = <<"EO_RPP"
INSERT INTO report_policy_published
  (report_id, adkim, aspf, p, sp, pct, rua)
VALUES (??)
EO_RPP
    ;
    return $self->query( $query,
        [ $id, @$pub{ qw/ adkim aspf p sp pct rua /} ]
    )
    or croak "failed to insert published policy";
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
    eval { $self->dbix->query( $query, @params ) } or croak $err;
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

Tested with SQLite and MySQL.

=head1 DESCRIPTION

Uses ANSI SQL syntax, keeping the SQL as portable as possible.

DB engine specific features are to be avoided.

=cut
