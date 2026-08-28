package Mail::DMARC::Report::Store::SQL;
our $VERSION = '2.20260827';
use strict;
use warnings;
use feature 'signatures';

use Carp;
use Data::Dumper;
use DBIx::Simple;
use File::ShareDir;

use Mail::DMARC::Report::Store::SQL::Grammars::MySQL;
use Mail::DMARC::Report::Store::SQL::Grammars::SQLite;
use Mail::DMARC::Report::Store::SQL::Grammars::PostgreSQL;

use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Aggregate;
use Mail::DMARC::Report::Aggregate::Record;
use Mail::DMARC::Policy;

my @AGG_FIELDS = qw/ messages aligned_both aligned_dkim aligned_spf aligned_none
    disp_none disp_quarantine disp_reject /;

my %FORWARDING_REASON
    = map { $_ => 1 } qw/ forwarded mailing_list trusted_forwarder /;

# A source is called aligned while its failures stay under this share of its
# own volume. Requiring exactly zero would label almost every real source as
# failing: retries, odd forwarders and low volume abuse of your domain put a
# few failures behind nearly everyone, and a bucket that catches everything
# sorts nothing.
my $FAILING_TOLERANCE = 0.02;

# Forwarding rarely accounts for every failure at a source that also has other
# problems, so the reasons only have to explain the bulk of them.
my $FORWARDING_SHARE = 0.5;

# ARC exists to carry authentication across a forwarding hop, so a receiver
# that overrode its policy on a passing ARC chain is telling you the mail was
# legitimately forwarded. The aggregate format has no field for that, so
# receivers report it as local_policy with the result in free text.
my $ARC_PASS = qr/\barc = pass\b/xi;

sub _explains_forwarding($reason) {
    return 1 if $FORWARDING_REASON{ $reason->{type} // '' };
    return 1
        if 'local_policy' eq ( $reason->{type} // '' )
        && defined $reason->{comment}
        && $reason->{comment} =~ $ARC_PASS;
    return 0;
}

sub save_aggregate( $self, $agg ) {

    $self->db_connect();

    croak "policy_published must be a Mail::DMARC::Policy object"
        if 'Mail::DMARC::Policy' ne ref $agg->policy_published;

    #warn Dumper($meta); ## no critic (Carp)
    foreach my $f (qw/ org_name email begin end /) {
        croak "meta field $f required" if !$agg->metadata->$f;
    }

    my $rid = $self->get_report_id($agg)
        or croak "failed to create report!";

    # on 6/8/2013, Microsoft spat out a bunch of reports with zero records.
    if ( !$agg->record ) {
        warn "\ta report with ZERO records! Illegal.\n";    ## no critic (Carp)
        return $rid;
    }

    foreach my $rec ( @{ $agg->record } ) {
        $self->insert_agg_record( $rid, $rec );
    }

    return $rid;
}

sub retrieve( $self, @args ) {
    my %args = @args;

    my $query = $self->grammar->select_report_query;
    my @params;

    if ( $args{rid} ) {
        $query .= $self->grammar->and_arg('r.id');
        push @params, $args{rid};
    }
    if ( $args{begin} ) {
        $query .= $self->grammar->and_arg( 'r.begin', '>=' );
        push @params, $args{begin};
    }
    if ( $args{end} ) {
        $query .= $self->grammar->and_arg( 'r.end', '<=' );
        push @params, $args{end};
    }
    if ( $args{author} ) {
        my ( $op, $val ) = $self->_negate_arg( $args{author} );
        $query .= $self->grammar->and_arg( 'a.org_name', $op );
        push @params, $val;
    }
    if ( $args{from_domain} ) {
        my ( $op, $val ) = $self->_negate_arg( $args{from_domain} );
        $query .= $self->grammar->and_arg( 'fd.domain', $op );
        push @params, $val;
    }

    my $sort_by = lc( $args{sort_by} || 'rid' );
    $sort_by = 'rid' if $sort_by eq 'id';

    my %allowed_sort = map { $_ => 1 } qw( rid author from_domain begin end );
    $sort_by = 'rid' if !$allowed_sort{$sort_by};

    my $sort_order = uc( $args{sort_order} || 'DESC' );
    $sort_order = 'DESC' if $sort_order ne 'ASC' && $sort_order ne 'DESC';

    $query .= $self->grammar->order_by( $sort_by, $sort_order );

    if ( defined $args{limit} ) {
        croak "limit must be a positive integer"
            if $args{limit} !~ /^\d+$/ || $args{limit} < 1;
        $query .= $self->grammar->limit( $args{limit} );
    }

    my $reports = $self->query( $query, \@params );

    foreach (@$reports) {
        $_->{begin} = join( " ", split( /T/, $self->epoch_to_iso( $_->{begin} ) ) );
        $_->{end}   = join( " ", split( /T/, $self->epoch_to_iso( $_->{end} ) ) );
    }
    return $reports;
}

sub _negate_arg( $self, $val ) {
    if ( substr( $val, 0, 1 ) eq '!' ) {
        return ( '!=', substr( $val, 1 ) );
    }
    return ( '=', $val );
}

sub next_todo($self) {

    if ( !exists $self->{_todo_list} ) {
        $self->{_todo_list}
            = $self->query( $self->grammar->select_todo_query, [ $self->time ] );
        return if !$self->{_todo_list};
    }

    my $next_todo = shift @{ $self->{_todo_list} };
    if ( !$next_todo ) {
        delete $self->{_todo_list};
        return;
    }

    my $agg = Mail::DMARC::Report::Aggregate->new();
    $self->populate_agg_metadata( \$agg, \$next_todo );

    my $pp = $self->get_report_policy_published( $next_todo->{rid} );
    $pp->{domain} = $next_todo->{from_domain};
    $agg->policy_published( Mail::DMARC::Policy->new(%$pp) );

    $self->populate_agg_records( \$agg, $next_todo->{rid} );
    return $agg;
}

sub retrieve_todo( $self, @args ) {

    # this method extracts the data from the SQL tables and populates a
    # list of Aggregate report objects with them.
    my $reports
        = $self->query( $self->grammar->select_todo_query, [ $self->time ] );
    my @reports_todo;
    return \@reports_todo if !@$reports;

    foreach my $report ( @{$reports} ) {

        my $agg = Mail::DMARC::Report::Aggregate->new();
        $self->populate_agg_metadata( \$agg, \$report );

        my $pp = $self->get_report_policy_published( $report->{rid} );
        $pp->{domain} = $report->{from_domain};
        $agg->policy_published( Mail::DMARC::Policy->new(%$pp) );

        $self->populate_agg_records( \$agg, $report->{rid} );
        push @reports_todo, $agg;
    }
    return \@reports_todo;
}

sub delete_report( $self, $report_id = undef ) {
    $report_id or croak "missing report ID";
    print "deleting report $report_id\n" if $self->verbose;

    # deletes with FK don't cascade in SQLite? Clean each table manually
    my $rows    = $self->query( $self->grammar->report_record_id, [$report_id] );
    my @row_ids = map { $_->{id} } @$rows;

    if (@row_ids) {
        foreach my $table (
            qw/ report_record_spf report_record_dkim report_record_reason /)
        {
            print "deleting $table rows " . join( ',', @row_ids ) . "\n"
                if $self->verbose;
            eval {
                $self->query( $self->grammar->delete_from_where_record_in($table),
                    \@row_ids );
            };

            # warn $@ if $@;
        }
    }
    foreach my $table (qw/ report_policy_published report_record report_error /) {
        print "deleting $table rows for report $report_id\n" if $self->verbose;
        eval {
            $self->query( $self->grammar->delete_from_where_report($table),
                [$report_id] );
        };

        # warn $@ if $@;
    }

    # In MySQL, where FK constraints DO cascade, this is the only query needed
    $self->query( $self->grammar->delete_report, [$report_id] );
    return 1;
}

sub get_domain_id( $self, $domain ) {
    croak "missing domain calling " . ( caller(0) )[3] if !$domain;
    my $r = $self->query( $self->grammar->select_domain_id, [$domain] );
    if ( $r && @$r ) {
        return $r->[0]{id};
    }
    return $self->query( $self->grammar->insert_domain, [$domain] );
}

sub get_author_id( $self, $meta ) {
    croak "missing author name" if !$meta->org_name;
    my $r = $self->query( $self->grammar->select_author_id, [ $meta->org_name ] );
    if ( $r && @$r ) {
        return $r->[0]{id};
    }
    carp "missing email" if !$meta->email;
    return $self->query( $self->grammar->insert_author,
        [ $meta->org_name, $meta->email, $meta->extra_contact_info ] );
}

sub get_report_id( $self, $aggr ) {

    my $meta = $aggr->metadata;
    my $pol  = $aggr->policy_published;

    # check if report exists
    my $author_id   = $self->get_author_id($meta)          or croak;
    my $from_dom_id = $self->get_domain_id( $pol->domain ) or croak;

    my $ids;
    if ( $meta->report_id ) {

        # reports arriving via the wire will have an author ID & report ID
        $ids = $self->query( $self->grammar->select_report_id,
            [ $meta->report_id, $author_id ] );
    }
    else {
        # Reports submitted by our local MTA will not have a report ID
        # They aggregate on the From domain, where the DMARC policy was discovered
        $ids = $self->query(
            $self->grammar->select_id_with_end,
            [ $from_dom_id, $self->time, $author_id ]
        );
    }

    if (@$ids) {    # report already exists
        return $self->{report_id} = $ids->[0]{id};
    }

    my $rid = $self->{report_id} = $self->query( $self->grammar->insert_report,
        [ $from_dom_id, $meta->begin, $meta->end, $author_id, $meta->uuid ] )
        or return;

    $self->insert_policy_published( $rid, $pol );
    return $rid;
}

sub get_report( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my @known = qw/ r.id a.org_name fd.domain r.begin r.end /;
    my %known = map { $_ => 1 } @known;

    my $where = '';
    my @where_params;

    # Optional reporting window, so a caller can scope the list the same way
    # the aggregate views are scoped. Compared against begin, matching how
    # those views attribute a report to a day.
    for my $pair ( [ since => 'r.begin', '>=' ], [ until => 'r.begin', '<=' ] ) {
        my ( $param, $column, $op ) = @$pair;
        next if !defined $args{$param};
        next if $args{$param} !~ /\A-?[0-9]+\z/x;
        $where .= $self->grammar->and_arg( $column, $op );
        push @where_params, $args{$param};
    }

    my ( $origin, $origin_params )
        = $self->_origin_filter( $args{reports} // 'all' );
    $where .= $origin;
    push @where_params, @$origin_params;

    # Per-column LIKE searches
    for my $pair ( [ search_domain => 'fd.domain' ],
        [ search_author => 'a.org_name' ] )
    {
        my ( $param, $col_name ) = @$pair;
        next unless $args{$param};
        my $safe = $args{$param};
        $safe =~ s/([%_!])/!$1/g;    # escape LIKE metacharacters using !
        $where .= " AND $col_name LIKE ? ESCAPE '!'";
        push @where_params, '%' . $safe . '%';
    }

    foreach my $known (@known) {
        next if !defined $args{$known};
        $where .= $self->grammar->and_arg($known);
        push @where_params, $args{$known};
    }

    my $total_recs    = $self->dbix->query( $self->grammar->count_reports )->list;
    my $filtered_recs = $total_recs;
    if ($where) {
        $filtered_recs
            = $self->dbix->query(
            $self->grammar->count_filtered_report_query . $where,
            @where_params )->list;
    }

    my $order = '';
    if ( $args{sort_col} && $known{ $args{sort_col} } ) {
        if ( $args{sort_dir} ) {
            $order = $self->grammar->order_by( $args{sort_col},
                $args{sort_dir} eq 'desc' ? ' DESC' : ' ASC' );
        }
    }

    my $query  = $self->grammar->select_report_query . $where . $order;
    my @params = @where_params;
    if ( $args{length} ) {
        my $start = $args{start} || 0;
        $start = 0 if $start < 0;
        $query .= $self->grammar->limit_args(2);
        push @params, $start, $args{length};
    }

    # warn "query: $query\n" . join(", ", @params) . "\n";
    my $reports = $self->query( $query, \@params );
    foreach (@$reports) {
        $_->{begin} = $self->epoch_to_iso( $_->{begin} );
        $_->{end}   = $self->epoch_to_iso( $_->{end} );
    }

    $self->attach_report_summaries($reports) if $args{summary};

    return {
        recordsTotal    => $total_recs,
        recordsFiltered => $filtered_recs,
        data            => $reports,
    };
}

# What each report contains, so a viewer has less reason to expand every row.
# Opt in from get_report: the callers that only want the report envelope should
# not pay for a second query.
sub attach_report_summaries( $self, $reports ) {
    my @rids = map { $_->{rid} } @$reports;
    return if !@rids;

    my $rows = $self->query( $self->grammar->select_report_summary_query, \@rids );

    my %by_rid;
    foreach my $row (@$rows) {
        my $summary = $by_rid{ $row->{rid} } ||= {
            ( map { $_ => 0 } @AGG_FIELDS ),
            header_from => {},
            envelope_to => {},
        };
        $summary->{$_} += $row->{$_} || 0 foreach @AGG_FIELDS;

        # A report names one domain per record; the set is usually a single
        # entry, occasionally a handful.
        foreach my $field (qw/ header_from envelope_to /) {
            next if !defined $row->{$field} || '' eq $row->{$field};
            $summary->{$field}{ $row->{$field} } = 1;
        }
    }

    foreach my $report (@$reports) {
        my $found = $by_rid{ $report->{rid} };
        if ( !$found ) {
            $report->{summary}
                = { ( map { $_ => 0 } @AGG_FIELDS ),
                    header_from => [], envelope_to => [] };
            next;
        }
        my %summary = map { $_ => $found->{$_} + 0 } @AGG_FIELDS;
        $summary{$_} = [ sort keys %{ $found->{$_} } ]
            foreach qw/ header_from envelope_to /;
        $report->{summary} = \%summary;
    }
    return;
}

sub get_report_policy_published( $self, $rid ) {
    my $pp = $self->query( $self->grammar->select_report_policy_published, [$rid] )
        ->[0];
    $pp->{p} ||= 'none';
    $pp = Mail::DMARC::Policy->new( v => 'DMARC1', %$pp );
    return $pp;
}

sub get_rr( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    # warn Dumper(\%args);
    croak "missing report ID (rid)!" if !defined $args{rid};

    my $rows = $self->query( $self->grammar->select_rr_query, [ $args{rid} ] );
    foreach (@$rows) {
        $_->{source_ip} = $self->any_inet_ntop( $_->{source_ip} )
            if $self->grammar->language ne 'postgresql';
        $_->{reasons}
            = $self->query( $self->grammar->select_report_reason, [ $_->{id} ] );
    }
    return { data => $rows, };
}

sub populate_agg_metadata( $self, $agg_ref, $report_ref ) {

    $$agg_ref->metadata->report_id( $$report_ref->{rid} );

    foreach my $f (qw/ org_name email extra_contact_info /) {
        $$agg_ref->metadata->$f( $self->config->{organization}{$f} );
    }
    foreach my $f (qw/ begin end /) {
        $$agg_ref->metadata->$f( $$report_ref->{$f} );
    }

    my $errors = $self->query( $self->grammar->select_report_error,
        [ $$report_ref->{rid} ] );
    foreach (@$errors) {
        $$agg_ref->metadata->error( $_->{error} );
    }
    return 1;
}

sub populate_agg_records( $self, $agg_ref, $rid ) {

    my $recs = $self->query( $self->grammar->select_rr_query, [$rid] );

    # aggregate the connections per IP-Disposition-DKIM-SPF uniqueness
    my ( %ips, %uniq, %pe, %auth, %ident, %reasons, %other );
    foreach my $rec (@$recs) {
        my $ip = $rec->{source_ip};
        $ip = $self->any_inet_ntop( $rec->{source_ip} )
            if $self->grammar->language ne 'postgresql';
        my $key = join( '-', $ip, @$rec{qw/ disposition dkim spf /} );  # hash slice
        $uniq{$key}++;
        $ips{$key} = $rec->{source_ip};
        $ident{$key}{header_from}   ||= $rec->{header_from};
        $ident{$key}{envelope_from} ||= $rec->{envelope_from};
        $ident{$key}{envelope_to}   ||= $rec->{envelope_to};

        $pe{$key}{disposition} ||= $rec->{disposition};
        $pe{$key}{dkim}        ||= $rec->{dkim};
        $pe{$key}{spf}         ||= $rec->{spf};

        $auth{$key}{spf}  ||= $self->get_row_spf( $rec->{id} );
        $auth{$key}{dkim} ||= $self->get_row_dkim( $rec->{id} );

        my $reasons = $self->get_row_reason( $rec->{id} );
        foreach my $reason (@$reasons) {
            my $type = $reason->{type} or next;
            $reasons{$key}{$type} = $reason->{comment};    # flatten reasons
        }
    }

    foreach my $u ( keys %uniq ) {
        my $record = Mail::DMARC::Report::Aggregate::Record->new(
            identifiers  => $ident{$u},
            auth_results => $auth{$u},
            row          => {
                source_ip => $self->grammar->language eq 'postgresql' ? $ips{$u}
                : $self->any_inet_ntop( $ips{$u} ),
                count            => $uniq{$u},
                policy_evaluated => {
                    %{ $pe{$u} },
                    $reasons{$u}
                    ? ( reason => [
                            map { { type => $_, comment => $reasons{$u}{$_} } }
                            sort keys %{ $reasons{$u} }
                        ]
                        )
                    : (),
                },
            }
        );
        $$agg_ref->record($record);
    }
    return $$agg_ref->record;
}

sub row_exists( $self, $rid, $rec ) {

    if ( !defined $rec->{row}{count} ) {
        print "new record\n" if $self->verbose;
        return;
    }

    my $rows = $self->query( $self->grammar->select_report_record,
        [ $rid, $rec->{row}{source_ip}, $rec->{row}{count}, ] );

    return 1 if @$rows;
    return;
}

sub insert_agg_record( $self, $report_id, $rec ) {

    return 1 if $self->row_exists( $report_id, $rec );

    my $row_id = $self->insert_rr( $report_id, $rec )
        or croak "failed to insert report row";

    my $reasons = $rec->row->policy_evaluated->reason;
    if ($reasons) {
        foreach my $reason (@$reasons) {
            next if !$reason || !$reason->{type};
            $self->insert_rr_reason( $row_id, $reason->{type}, $reason->{comment} );
        }
    }

    my $spf_ref = $rec->auth_results->spf;
    if ($spf_ref) {
        foreach my $spf (@$spf_ref) {
            $self->insert_rr_spf( $row_id, $spf );
        }
    }

    my $dkim = $rec->auth_results->dkim;
    if ($dkim) {
        foreach my $sig (@$dkim) {
            next if !$sig || !$sig->{domain};
            $self->insert_rr_dkim( $row_id, $sig );
        }
    }
    return 1;
}

sub insert_error( $self, $rid, $error ) {

    # wait >5m before trying to deliver this report again
    $self->query( $self->grammar->insert_error(0),
        [ $self->time + ( 5 * 60 ), $rid ] );

    return $self->query( $self->grammar->insert_error(1), [ $rid, $error ] );
}

sub insert_rr_reason( $self, $row_id, $type, $comment ) {
    return $self->query( $self->grammar->insert_rr_reason,
        [ $row_id, $type, ( $comment || '' ) ] );
}

sub insert_rr_dkim( $self, $row_id, $dkim ) {
    my ( @fields, @values );
    foreach (qw/ domain selector result human_result /) {
        next if !defined $dkim->{$_};
        if ( 'domain' eq $_ ) {
            push @fields, 'domain_id';
            push @values, $self->get_domain_id( $dkim->{domain} );
            next;
        }
        push @fields, $_;
        push @values, $dkim->{$_};
    }
    my $query = $self->grammar->insert_rr_dkim( \@fields );
    $self->query( $query, [ $row_id, @values ] );
    return 1;
}

sub insert_rr_spf( $self, $row_id, $spf ) {
    my ( @fields, @values );
    for (qw/ domain scope result /) {
        next if !defined $spf->{$_};
        if ( 'domain' eq $_ ) {
            push @fields, 'domain_id';
            push @values, $self->get_domain_id( $spf->{domain} );
            next;
        }
        push @fields, $_;
        push @values, $spf->{$_};
    }
    my $query = $self->grammar->insert_rr_spf( \@fields );
    $self->query( $query, [ $row_id, @values ] );
    return 1;
}

sub insert_rr( $self, $report_id, $rec ) {
    $report_id or croak "report ID required?!";
    my $query = $self->grammar->insert_rr;

    my $ip = $rec->row->source_ip;
    $ip = $self->any_inet_pton($ip) if $self->grammar->language ne 'postgresql';
    my @args = ( $report_id, $ip, $rec->{row}{count}, );
    foreach my $f (qw/ header_from envelope_to envelope_from /) {
        push @args,
            $rec->identifiers->$f
            ? $self->get_domain_id( $rec->identifiers->$f )
            : undef;
    }
    push @args, map { $rec->row->policy_evaluated->$_ } qw/ disposition dkim spf /;
    my $rr_id = $self->query( $query, \@args ) or croak;
    return $self->{report_row_id} = $rr_id;
}

sub insert_policy_published( $self, $id, $pub ) {
    my $query = $self->grammar->insert_policy_published;
    $self->query( $query, [ $id, @$pub{qw/ adkim aspf p sp pct rua /} ] );
    return 1;
}

sub db_connect($self) {

    my $dsn  = $self->config->{report_store}{dsn} or croak;
    my $user = $self->config->{report_store}{user};
    my $pass = $self->config->{report_store}{pass};

    # cacheing
    if ( $self->{grammar} && $self->{dbix} ) {
        my $cached_grammar_type = $self->{grammar}->dsn;
        if ( $dsn =~ /$cached_grammar_type/ ) {
            return $self->{dbix};    # caching
        }
    }

    my $needs_tables;

    $self->{grammar} = undef;
    my %opts;

    if ( $dsn =~ /sqlite/i ) {
        my ($db) = ( split /=/, $dsn )[-1];
        if ( !$db || $db eq ':memory:' || !-e $db ) {
            my $schema = 'mail_dmarc_schema.sqlite';
            $needs_tables = $self->get_db_schema($schema)
                or croak
                "can't locate DB $db AND can't find $schema! Create $db manually.\n";
        }
        $self->{grammar} = Mail::DMARC::Report::Store::SQL::Grammars::SQLite->new();
    }
    elsif ( $dsn =~ /mysql/i ) {
        $opts{'mysql_enable_utf8mb4'} = 1;
        $self->{grammar} = Mail::DMARC::Report::Store::SQL::Grammars::MySQL->new();
    }
    elsif ( $dsn =~ /pg/i ) {
        $self->{grammar}
            = Mail::DMARC::Report::Store::SQL::Grammars::PostgreSQL->new();
    }
    else {
        croak "can't determine database type, so unable to load grammar.\n";
    }

    $self->{dbix} = DBIx::Simple->connect( $dsn, $user, $pass, \%opts )
        or return $self->error( DBIx::Simple->error );

    if ($needs_tables) {
        $self->apply_db_schema($needs_tables);
    }

    return $self->{dbix};
}

sub db_check_err( $self, $err ) {
    ## no critic (PackageVars)
    return if !defined $DBI::errstr;
    return if !$DBI::errstr;
    return if $DBI::errstr eq 'DBI error: ';
    croak $err . $DBI::errstr;
}

sub dbix($self) {
    return $self->{dbix} if $self->{dbix};
    return $self->db_connect();
}

sub apply_db_schema( $self, $file ) {
    my $setup = $self->slurp($file);
    foreach ( split /;/, $setup ) {

        # warn "$_\n";
        $self->dbix->query($_);
    }
    return;
}

sub get_db_schema( $self, $file ) {
    return "share/$file" if -f "share/$file";                   # when testing
    return File::ShareDir::dist_file( 'Mail-DMARC', $file );    # when installed
}

sub query( $self, $query, $params = undef, @extra ) {

    my @c   = caller;
    my $err = sprintf( "query called by %s, %s\n", $c[0], $c[2] ) . "\t$query\n\t";

    my @params;
    if ( defined $params ) {
        @params = ref $params eq 'ARRAY' ? @$params : $params;
        no warnings;    ## no critic (NoWarnings)
        $err .= join( ', ', @params );
    }

    croak "too many arguments to exec_query!" if @extra;

    my $dbix = $self->db_connect() or croak DBIx::Simple->error;

    return $self->query_insert( $query, $err, @params ) if $query =~ /^INSERT/ix;
    return $self->query_replace( $query, $err, @params )
        if $query =~ /^(?:REPLACE|UPDATE)/ix;
    return $self->query_delete( $query, $err, @params )
        if $query =~ /^(?:DELETE|TRUNCATE)/ix;
    return $self->query_any( $query, $err, @params );
}

sub query_any( $self, $query, $err, @params ) {

    # warn "query: $query\n" . join(", ", @params) . "\n";
    my $r;
    eval { $r = $self->dbix->query( $query, @params )->hashes; } or print '';
    $self->db_check_err($err);
    die "something went wrong with: $err\n" if !$r;    ## no critic (Carp)
    return $r;
}

sub query_insert( $self, $query, $err, @params ) {
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

sub query_replace( $self, $query, $err, @params ) {
    $self->dbix->query( $query, @params ) or croak $err;
    $self->db_check_err($err);
    return 1;    # sorry, no indication of success
}

sub query_delete( $self, $query, $err, @params ) {
    my $affected = $self->dbix->query( $query, @params )->rows or croak $err;
    $self->db_check_err($err);
    return $affected;
}

sub get_row_spf( $self, $rowid ) {
    return $self->query( $self->grammar->select_row_spf, [$rowid] );
}

sub get_row_dkim( $self, $rowid ) {
    return $self->query( $self->grammar->select_row_dkim, [$rowid] );
}

sub get_row_reason( $self, $rowid ) {
    return $self->query( $self->grammar->select_row_reason, [$rowid] );
}

# A store doubles as the queue for reports this installation is preparing to
# send, and those are about other people's domains as seen by us. Reports about
# our domains as seen by others are a different population, and blending the
# two makes the headline pass rate answer neither question. They are told apart
# by who authored the report, which is the only signal the schema carries; an
# installation that has changed its org_name will read its older outgoing
# reports as received.
sub _origin_filter( $self, $kind ) {
    return ( '', [] ) if 'all' eq ( $kind // '' );

    my $org = $self->config->{organization}{org_name};
    return ( '', [] ) if !$org;

    my $op = 'outgoing' eq ( $kind // '' ) ? '=' : '<>';
    return ( $self->grammar->and_arg( 'a.org_name', $op ), [$org] );
}

# Reports are attributed to the day their window begins, matching the day
# bucketing in the grammar, so a window filter compares against begin alone.
sub _agg_where( $self, $args ) {
    my ( $where, @params ) = ('');

    my @filters = (
        [ since       => 'r.begin',     '>=' ],
        [ until       => 'r.begin',     '<=' ],
        [ from_domain => 'fd.domain',   '=' ],
        [ author      => 'a.org_name',  '=' ],
    );

    foreach my $filter (@filters) {
        my ( $arg, $column, $op ) = @$filter;
        next if !defined $args->{$arg};
        $where .= $self->grammar->and_arg( $column, $op );
        push @params, $args->{$arg};
    }

    if ( defined $args->{source_ip} ) {
        $where .= $self->grammar->and_arg('rr.source_ip');
        push @params,
            $self->grammar->language eq 'postgresql'
            ? $args->{source_ip}
            : $self->any_inet_pton( $args->{source_ip} );
    }

    $where .= $self->grammar->and_failing if $args->{failing_only};

    my ( $origin, $origin_params )
        = $self->_origin_filter( $args->{reports} // 'received' );
    $where .= $origin;
    push @params, @$origin_params;

    return ( $where, \@params );
}

# DBI hands back aggregates as strings; the JSON views need numbers.
sub _agg_numify($rows) {
    foreach my $row (@$rows) {
        foreach my $field ( @AGG_FIELDS,
            qw/ day reporters first_seen last_seen reports / )
        {
            $row->{$field} += 0 if defined $row->{$field};
        }
    }
    return $rows;
}

sub _agg_ips_to_text( $self, $rows ) {
    return $rows if $self->grammar->language eq 'postgresql';
    foreach my $row (@$rows) {
        $row->{source_ip} = $self->any_inet_ntop( $row->{source_ip} )
            if $row->{source_ip};
    }
    return $rows;
}

sub get_timeseries( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my ( $where, $params ) = $self->_agg_where( \%args );
    my $rows
        = $self->query( $self->grammar->select_timeseries_query($where), $params );

    return { data => _agg_numify($rows) };
}

# Totals are summed from the daily buckets rather than queried separately, so
# the tiles and the chart can never disagree.
sub _sum_timeseries( $self, %args ) {
    my $days = $self->get_timeseries(%args)->{data};

    my %totals = map { $_ => 0 } @AGG_FIELDS;
    foreach my $day (@$days) {
        $totals{$_} += $day->{$_} || 0 for @AGG_FIELDS;
    }
    $totals{dmarc_pass} = $totals{messages} - $totals{aligned_none};
    $totals{days}       = scalar @$days;

    return \%totals;
}

sub get_summary( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my %summary = ( current => $self->_sum_timeseries(%args) );

    # An equal-length window immediately before this one, for the deltas.
    if ( defined $args{since} && defined $args{until} ) {
        my $span = $args{until} - $args{since};
        $summary{previous} = $self->_sum_timeseries( %args,
            since => $args{since} - $span - 1,
            until => $args{since} - 1,
        );
    }

    return \%summary;
}

sub get_sources( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my ( $where, $params ) = $self->_agg_where( \%args );
    my $sources
        = $self->query( $self->grammar->select_sources_query($where), $params );
    my ( $fwhere, $fparams )
        = $self->_agg_where( { %args, failing_only => 1 } );
    my $reasons = $self->query(
        $self->grammar->select_source_reasons_query($fwhere), $fparams );

    $self->_agg_ips_to_text($sources);
    $self->_agg_ips_to_text($reasons);
    _agg_numify($sources);

    my %by_ip;
    foreach my $reason (@$reasons) {
        push @{ $by_ip{ $reason->{source_ip} } },
            {
            type     => $reason->{type},
            comment  => $reason->{comment},
            messages => ( $reason->{messages} || 0 ) + 0,
            };
    }

    foreach my $source (@$sources) {
        $source->{reasons} = $by_ip{ $source->{source_ip} } || [];
        $source->{bucket}  = _classify_source($source);
    }

    my $sort = $args{sort_col} && $args{sort_col} eq 'messages'
        ? sub { $b->{messages} <=> $a->{messages} }
        : sub { $b->{aligned_none} <=> $a->{aligned_none}
                    || $b->{messages} <=> $a->{messages} };
    my @sorted = sort $sort @$sources;

    my $total = scalar @sorted;

    # Summed before paging: a caller showing each source's share of the window
    # cannot derive the denominator from one page.
    my $messages = 0;
    $messages += $_->{messages} || 0 foreach @sorted;

    if ( $args{length} ) {
        my $start = $args{start} || 0;
        $start = 0 if $start < 0;
        @sorted = splice @sorted, $start, $args{length};
    }

    return {
        recordsTotal  => $total,
        messagesTotal => $messages,
        data          => \@sorted,
    };
}

# Ranks a source by whether it needs attention. Telling a misconfigured sender
# apart from an unauthenticated one needs the auth detail tables, which the
# list query does not join; get_source_detail makes that distinction.
sub _classify_source($source) {
    my $failing = $source->{aligned_none} || 0;
    my $total   = $source->{messages}     || 0;

    return 'aligned' if !$failing;
    return 'aligned' if $total && ( $failing / $total ) < $FAILING_TOLERANCE;

    # The largest single reason, not their sum: one record may carry several,
    # and each row already counts that record's whole volume.
    my $forwarded = 0;
    foreach my $reason ( @{ $source->{reasons} } ) {
        next if !_explains_forwarding($reason);
        $forwarded = $reason->{messages} if $reason->{messages} > $forwarded;
    }
    return 'forwarded' if $forwarded >= $failing * $FORWARDING_SHARE;

    return 'failing';
}

sub get_source_detail( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;
    croak "missing source_ip" if !defined $args{source_ip};

    my ( $where, $params ) = $self->_agg_where( \%args );

    my $records
        = $self->query( $self->grammar->select_source_detail_query($where), $params );
    my $dkim
        = $self->query( $self->grammar->select_source_dkim_query($where), $params );
    my $spf
        = $self->query( $self->grammar->select_source_spf_query($where), $params );

    _agg_numify($_) for $records, $dkim, $spf;

    my $failing = 0;
    $failing += $_->{messages}
        foreach grep { 'pass' ne ( $_->{dkim} // '' ) && 'pass' ne ( $_->{spf} // '' ) }
        @$records;

    my ( $fwhere, $fparams )
        = $self->_agg_where( { %args, failing_only => 1 } );
    my $failing_auth
        = @{ $self->query( $self->grammar->select_source_dkim_query($fwhere),
            $fparams ) }
        || @{ $self->query( $self->grammar->select_source_spf_query($fwhere),
            $fparams ) };

    my $bucket
        = !$failing      ? 'aligned'
        : $failing_auth  ? 'broken'
        :                  'unauthenticated';

    return {
        source_ip => $args{source_ip},
        bucket    => $bucket,
        records   => $records,
        dkim      => $dkim,
        spf       => $spf,
    };
}

sub get_report_domains( $self, @args ) {
    croak "invalid parameters" if @args % 2;
    my %args = @args;

    my ( $where, $params )
        = $self->_origin_filter( $args{reports} // 'received' );
    my $rows
        = $self->query( $self->grammar->select_report_domains_query($where),
        $params );

    return { data => _agg_numify($rows) };
}

sub grammar($self) {
    $self->db_connect();
    return $self->{grammar};
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Store::SQL - store and retrieve reports from a SQL RDBMS

=head1 VERSION

version 2.20260827

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

This software is copyright (c) 2026 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
