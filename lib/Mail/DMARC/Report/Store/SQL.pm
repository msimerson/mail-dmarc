package Mail::DMARC::Report::Store::SQL;
our $VERSION = '1.20200108';
use strict;
use warnings;

use Carp;
use Data::Dumper;
use DBIx::Simple;
use File::ShareDir;

use Mail::DMARC::Report::Store::SQL::Grammars::MySQL;
use Mail::DMARC::Report::Store::SQL::Grammars::SQLite;
use Mail::DMARC::Report::Store::SQL::Grammars::PostgreSQL;

use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Aggregate;

sub save_aggregate {
    my ( $self, $agg ) = @_;

    $self->db_connect();

    croak "policy_published must be a Mail::DMARC::Policy object"
        if 'Mail::DMARC::Policy' ne ref $agg->policy_published;

    #warn Dumper($meta); ## no critic (Carp)
    foreach my $f ( qw/ org_name email begin end / ) {
        croak "meta field $f required" if ! $agg->metadata->$f;
    }

    my $rid = $self->get_report_id( $agg )
        or croak "failed to create report!";

    # on 6/8/2013, Microsoft spat out a bunch of reports with zero records.
    if ( ! $agg->record ) {
        warn "\ta report with ZERO records! Illegal.\n"; ## no critic (Carp)
        return $rid;
    };

    foreach my $rec ( @{ $agg->record } ) {
        $self->insert_agg_record($rid, $rec);
    };

    return $rid;
}

sub retrieve {
    my ( $self, %args ) = @_;

    my $query = $self->grammar->select_report_query;
    my @params;

    if ( $args{rid} ) {
        $query .= $self->grammar->and_arg('r.id');
        push @params, $args{rid};
    };
    if ( $args{begin} ) {
        $query .= $self->grammar->and_arg('r.begin', '>=');
        push @params, $args{begin};
    };
    if ( $args{end} ) {
        $query .= $self->grammar->and_arg('r.end', '<=');
        push @params, $args{end};
    };
    if ( $args{author} ) {
        $query .= $self->grammar->and_arg('a.org_name');
        push @params, $args{author};
    };
    if ( $args{from_domain} ) {
        $query .= $self->grammar->and_arg('fd.domain');
        push @params, $args{from_domain};
    };

    my $reports = $self->query( $query, \@params );

    foreach (@$reports ) {
        $_->{begin} = join(" ", split(/T/, $self->epoch_to_iso( $_->{begin} )));
        $_->{end} = join(" ", split(/T/, $self->epoch_to_iso( $_->{end} )));
    };
    return $reports;
}

sub next_todo {
    my ( $self ) = @_;

    if ( ! exists $self->{ _todo_list } ) {
        $self->{_todo_list} = $self->query( $self->grammar->select_todo_query, [ time ] );
        return if ! $self->{_todo_list};
    }

    my $next_todo = shift @{ $self->{_todo_list} };
    if ( ! $next_todo ) {
        delete $self->{_todo_list};
        return;
    }

    my $agg = Mail::DMARC::Report::Aggregate->new();
    $self->populate_agg_metadata( \$agg, \$next_todo );

    my $pp = $self->get_report_policy_published( $next_todo->{rid} );
    $pp->{domain} = $next_todo->{from_domain};
    $agg->policy_published( Mail::DMARC::Policy->new( %$pp ) );

    $self->populate_agg_records( \$agg, $next_todo->{rid} );
    return $agg;
}

sub retrieve_todo {
    my ( $self, @args ) = @_;

    # this method extracts the data from the SQL tables and populates a
    # list of Aggregate report objects with them.
    my $reports = $self->query( $self->grammar->select_todo_query, [ time ] );

    my @reports_todo;
    return \@reports_todo if ! scalar @$reports;

    foreach my $report ( @{ $reports } ) {

        my $agg = Mail::DMARC::Report::Aggregate->new();
        $self->populate_agg_metadata( \$agg, \$report );

        my $pp = $self->get_report_policy_published( $report->{rid} );
        $pp->{domain} = $report->{from_domain};
        $agg->policy_published( Mail::DMARC::Policy->new( %$pp ) );

        $self->populate_agg_records( \$agg, $report->{rid} );
        push @reports_todo, $agg;
    }
    return \@reports_todo;
}

sub delete_report {
    my $self = shift;
    my $report_id = shift or croak "missing report ID";
    print "deleting report $report_id\n" if $self->verbose;

    # deletes with FK don't cascade in SQLite? Clean each table manually
    my $rows = $self->query( $self->grammar->report_record_id, [$report_id] );
    my @row_ids = map { $_->{id} } @$rows;

    if (scalar @row_ids) {
        foreach my $table (qw/ report_record_spf report_record_dkim report_record_reason /) {
            print "deleting $table rows " . join(',', @row_ids) . "\n" if $self->verbose;
            eval { $self->query( $self->grammar->delete_from_where_record_in($table, \@row_ids)); };
            # warn $@ if $@;
        }
    }
    foreach my $table (qw/ report_policy_published report_record report_error /) {
        print "deleting $table rows for report $report_id\n" if $self->verbose;
        eval { $self->query( $self->grammar->delete_from_where_report( $table, [$report_id] )); };
        # warn $@ if $@;
    }

    # In MySQL, where FK constraints DO cascade, this is the only query needed
    $self->query( $self->grammar->delete_report, [$report_id] );
    return 1;
}

sub get_domain_id {
    my ( $self, $domain ) = @_;
    croak "missing domain calling " . ( caller(0) )[3] if !$domain;
    my $r = $self->query( $self->grammar->select_domain_id, [$domain] );
    if ( $r && scalar @$r ) {
        return $r->[0]{id};
    }
    return $self->query( $self->grammar->insert_domain, [$domain]);
}

sub get_author_id {
    my ( $self, $meta ) = @_;
    croak "missing author name" if !$meta->org_name;
    my $r = $self->query( 
        $self->grammar->select_author_id,
        [ $meta->org_name ]
    );
    if ( $r && scalar @$r ) {
        return $r->[0]{id};
    }
    carp "missing email" if !$meta->email;
    return $self->query(
        $self->grammar->insert_author,
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
        $self->grammar->select_report_id,
        [ $meta->report_id, $author_id ]
        );
    }
    else {
    # Reports submitted by our local MTA will not have a report ID
    # They aggregate on the From domain, where the DMARC policy was discovered
        $ids = $self->query(
        $self->grammar->select_id_with_end,
        [ $from_dom_id, time, $author_id ]
        );
    };

    if ( scalar @$ids ) { # report already exists
        return $self->{report_id} = $ids->[0]{id};
    }

    my $rid = $self->{report_id} = $self->query(
        $self->grammar->insert_report,
        [ $from_dom_id, $meta->begin, $meta->end, $author_id, $meta->uuid ]
    ) or return;

    $self->insert_policy_published( $rid, $pol );
    return $rid;
}

sub get_report {
    my ($self,@args) = @_;
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my $query = $self->grammar->select_report_query;
    my @params;
    my @known = qw/ r.id a.org_name fd.domain r.begin r.end /;
    my %known = map { $_ => 1 } @known;

    # TODO: allow custom search ops?  'searchOper' => 'eq',
    if ( $args{searchField} && $known{ $args{searchField} } ) {
        $query .= $self->grammar->and_arg($args{searchField});
        push @params, $args{searchString};
    };

    foreach my $known ( @known ) {
        next if ! defined $args{$known};
        $query .= $self->grammar->and_arg($known);
        push @params, $args{$known};
    };
    if ( $args{sidx} && $known{$args{sidx}} ) {
        if ( $args{sord} ) {
            $query .= $self->grammar->order_by($args{sidx}, $args{sord} eq 'desc' ? ' DESC' : ' ASC');
        };
    };
    my $total_recs = $self->dbix->query($self->grammar->count_reports)->list;
    my $total_pages = 0;
    if ( $args{rows} ) {
        if ( $args{page} ) {
            $total_pages = POSIX::ceil($total_recs / $args{rows});
            my $start = ($args{rows} * $args{page}) - $args{rows};
            $start = 0 if $start < 0;
            $query .= $self->grammar->limit_args(2);
            push @params, $start, $args{rows};
        }
        else {
            $query .= $self->grammar->limit_args;
            push @params, $args{rows};
        };
    };

    # warn "query: $query\n" . join(", ", @params) . "\n";
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
}

sub get_report_policy_published {
    my ($self, $rid) = @_;
    my $pp = $self->query($self->grammar->select_report_policy_published, [ $rid ] )->[0];
    $pp->{p} ||= 'none';
    $pp = Mail::DMARC::Policy->new( v=>'DMARC1', %$pp );
    return $pp;
}

sub get_rr {
    my ($self,@args) = @_;
    croak "invalid parameters" if @args % 2;
    my %args = @args;
    # warn Dumper(\%args);
    croak "missing report ID (rid)!" if ! defined $args{rid};

    my $rows = $self->query( $self->grammar->select_rr_query, [ $args{rid} ] );
    foreach ( @$rows ) {
        $_->{source_ip} = $self->any_inet_ntop( $_->{source_ip} ) if $self->grammar->language ne 'postgresql';
        $_->{reasons} = $self->query($self->grammar->select_report_reason, [ $_->{id} ] );
    };
    return {
        cur_page    => 1,
        total_pages => 1,
        total_rows  => scalar @$rows,
        rows        => $rows,
    };
}

sub populate_agg_metadata {
    my ($self, $agg_ref, $report_ref) = @_;

    $$agg_ref->metadata->report_id( $$report_ref->{rid} );

    foreach my $f ( qw/ org_name email extra_contact_info / ) {
        $$agg_ref->metadata->$f( $self->config->{organization}{$f} );
    };
    foreach my $f ( qw/ begin end / ) {
        $$agg_ref->metadata->$f( $$report_ref->{$f} );
    };

    my $errors = $self->query($self->grammar->select_report_error,
            [ $$report_ref->{rid} ]
        );
    foreach ( @$errors ) {
        $$agg_ref->metadata->error( $_->{error} );
    };
    return 1;
}

sub populate_agg_records {
    my ($self, $agg_ref, $rid) = @_;

    my $recs = $self->query( $self->grammar->select_rr_query, [ $rid ] );

    # aggregate the connections per IP-Disposition-DKIM-SPF uniqueness
    my (%ips, %uniq, %pe, %auth, %ident, %reasons, %other);
    foreach my $rec ( @$recs ) {
        my $ip = $rec->{source_ip};
        $ip = $self->any_inet_ntop($rec->{source_ip}) if $self->grammar->language ne 'postgresql';
        my $key = join('-', $ip,
                @$rec{ qw/ disposition dkim spf / }); # hash slice
        $uniq{ $key }++;
        $ips{$key} = $rec->{source_ip};
        $ident{$key}{header_from}   ||= $rec->{header_from};
        $ident{$key}{envelope_from} ||= $rec->{envelope_from};
        $ident{$key}{envelope_to}   ||= $rec->{envelope_to};

        $pe{$key}{disposition} ||= $rec->{disposition};
        $pe{$key}{dkim}   ||= $rec->{dkim};
        $pe{$key}{spf}    ||= $rec->{spf};

        $auth{$key}{spf}  ||= $self->get_row_spf($rec->{id});
        $auth{$key}{dkim} ||= $self->get_row_dkim($rec->{id});

        my $reasons = $self->get_row_reason( $rec->{id} );
        foreach my $reason ( @$reasons ) {
            my $type = $reason->{type} or next;
            $reasons{$key}{$type} = $reason->{comment};   # flatten reasons
        }
    }

    foreach my $u ( keys %uniq ) {
        my $record = Mail::DMARC::Report::Aggregate::Record->new(
            identifiers  => $ident{$u},
            auth_results => $auth{$u},
            row => {
                source_ip => $self->grammar->language eq 'postgresql' ? $ips{$u} : $self->any_inet_ntop( $ips{$u} ),
                count     => $uniq{ $u },
                policy_evaluated => {
                    %{ $pe{$u} },
                    $reasons{$u} ? ( reason => [ map { { type => $_, comment => $reasons{$u}{$_} } } sort keys %{ $reasons{$u} } ] ) : (),
                },
            }
        );
        $$agg_ref->record( $record );
    }
    return $$agg_ref->record;
}

sub row_exists {
    my ($self, $rid, $rec ) = @_;

    if ( ! defined $rec->{row}{count} ) {
        print "new record\n" if $self->verbose;
        return;
    };

    my $rows = $self->query(
        $self->grammar->select_report_record,
        [ $rid, $rec->{row}{source_ip}, $rec->{row}{count}, ]
    );

    return 1 if scalar @$rows;
    return;
}

sub insert_agg_record {
    my ($self, $row_id, $rec) = @_;

    return 1 if $self->row_exists( $row_id, $rec);

    $row_id = $self->insert_rr( $row_id, $rec )
        or croak "failed to insert report row";

    my $reasons = $rec->row->policy_evaluated->reason;
    if ( $reasons ) {
        foreach my $reason ( @$reasons ) {
            next if !$reason || !$reason->{type};
            $self->insert_rr_reason( $row_id, $reason->{type}, $reason->{comment} );
        };
    }

    my $spf_ref = $rec->auth_results->spf;
    if ( $spf_ref ) {
        foreach my $spf (@$spf_ref) {
            $self->insert_rr_spf( $row_id, $spf );
        }
    }

    my $dkim = $rec->auth_results->dkim;
    if ($dkim) {
        foreach my $sig (@$dkim) {
            next if ! $sig || ! $sig->{domain};
            $self->insert_rr_dkim( $row_id, $sig );
        }
    }
    return 1;
}

sub insert_error {
    my ( $self, $rid, $error ) = @_;
    # wait >5m before trying to deliver this report again
    $self->query($self->grammar->insert_error(0), [time + (5*60), $rid]);

    return $self->query(
        $self->grammar->insert_error(1),
        [ $rid, $error ]
    );
}

sub insert_rr_reason {
    my ( $self, $row_id, $type, $comment ) = @_;
    return $self->query(
        $self->grammar->insert_rr_reason,
        [ $row_id, $type, ($comment || '') ]
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
    my $query = $self->grammar->insert_rr_dkim(\@fields);
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
    my $query = $self->grammar->insert_rr_spf(\@fields);
    $self->query( $query, [ $row_id, @values ]);
    return 1;
}

sub insert_rr {
    my ( $self, $report_id, $rec ) = @_;
    $report_id or croak "report ID required?!";
    my $query = $self->grammar->insert_rr;

    my $ip = $rec->row->source_ip;
    $ip = $self->any_inet_pton( $ip ) if $self->grammar->language ne 'postgresql';
    my @args = ( $report_id,
        $ip,
        $rec->{row}{count},
    );
    foreach my $f ( qw/ header_from envelope_to envelope_from / ) {
        push @args, $rec->identifiers->$f ?
            $self->get_domain_id( $rec->identifiers->$f ) : undef;
    };
    push @args, map { $rec->row->policy_evaluated->$_ } qw/ disposition dkim spf /;
    my $rr_id = $self->query( $query, \@args ) or croak;
    return $self->{report_row_id} = $rr_id;
}

sub insert_policy_published {
    my ( $self, $id, $pub ) = @_;
    my $query = $self->grammar->insert_policy_published;
    $self->query( $query,
        [ $id, @$pub{ qw/ adkim aspf p sp pct rua /} ]
    );
    return 1;
}

sub db_connect {
    my $self = shift;

    my $dsn  = $self->config->{report_store}{dsn} or croak;
    my $user = $self->config->{report_store}{user};
    my $pass = $self->config->{report_store}{pass};

    if ($self->{grammar} and $self->{grammar}->dsn =~ /$dsn/i) {
        return $self->{dbix} if $self->{dbix};    # caching
    }

    my $needs_tables;

    $self->{grammar} = undef;
    if ($dsn =~ /sqlite/i) {
        my ($db) = ( split /=/, $dsn )[-1];
        if ( !$db || $db eq ':memory:' || !-e $db ) {
            my $schema = 'mail_dmarc_schema.sqlite';
            $needs_tables = $self->get_db_schema($schema)
                or croak
                "can't locate DB $db AND can't find $schema! Create $db manually.\n";
        }
        $self->{grammar} = Mail::DMARC::Report::Store::SQL::Grammars::SQLite->new();
    } elsif ($dsn =~ /mysql/i) {
        $self->{grammar} = Mail::DMARC::Report::Store::SQL::Grammars::MySQL->new();
    } elsif ($dsn =~ /pg/i) {
        $self->{grammar} = Mail::DMARC::Report::Store::SQL::Grammars::PostgreSQL->new();
    } else {
        croak "can't determine database type, so unable to load grammar.\n";
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
    # warn "$_\n";
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

    return $self->query_insert( $query, $err, @params )  if $query =~ /^INSERT/ix;
    return $self->query_replace( $query, $err, @params ) if $query =~ /^(?:REPLACE|UPDATE)/ix;
    return $self->query_delete( $query, $err, @params )  if $query =~ /^(?:DELETE|TRUNCATE)/ix;
    return $self->query_any( $query, $err, @params );
}

sub query_any {
    my ( $self, $query, $err, @params ) = @_;
    # warn "query: $query\n" . join(", ", @params) . "\n";
    my $r;
    eval { $r = $self->dbix->query( $query, @params )->hashes; } or print '';
    $self->db_check_err($err);
    die "something went wrong with: $err\n" if ! $r; ## no critic (Carp)
    return $r;
}

sub query_insert {
    my ( $self, $query, $err, @params ) = @_;
    eval { $self->dbix->query( $query, @params ) } or do {
        warn DBIx::Simple->error . "\n";
        croak $err;
    };
    $self->db_check_err($err);

    # If the table has no autoincrement field, last_insert_id is zero
    my ( undef, undef, $table ) = split /\s+/, $query;
    ($table) = split( /\(/, $table ) if $table =~ /\(/;
    $table =~ s/^"|"$//g;
    croak "unable to determine table in query: $query" if !$table;
    return $self->dbix->last_insert_id( undef, undef, $table, undef );
}

sub query_replace {
    my ( $self, $query, $err, @params ) = @_;
    $self->dbix->query( $query, @params ) or croak $err;
    $self->db_check_err($err);
    return 1;    # sorry, no indication of success
}

sub query_delete {
    my ( $self, $query, $err, @params ) = @_;
    my $affected = $self->dbix->query( $query, @params )->rows or croak $err;
    $self->db_check_err($err);
    return $affected;
}

sub get_row_spf {
    my ($self, $rowid) = @_;
    return $self->query( $self->grammar->select_row_spf, [ $rowid ] );
}

sub get_row_dkim {
    my ($self, $rowid) = @_;
    return $self->query( $self->grammar->select_row_dkim, [ $rowid ] );
}

sub get_row_reason {
    my ($self, $rowid) = @_;
    return $self->query( $self->grammar->select_row_reason, [ $rowid ] );
}

sub grammar {
    my $self = shift;
    $self->db_connect();
    return $self->{grammar};
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Store::SQL - store and retrieve reports from a SQL RDBMS

=head1 VERSION

version 1.20200108

=head1 DESCRIPTION

Uses ANSI SQL syntax, keeping the SQL as portable as possible.

DB engine specific features are to be avoided.

=head1 SYPNOSIS

Store and retrieve DMARC reports from SQL data store.

Tested with SQLite, MySQL and PostgreSQL.

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

This software is copyright (c) 2020 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

