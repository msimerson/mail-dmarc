package Mail::DMARC::Report::Store::SQL;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use DBIx::Simple;
use File::ShareDir;

use parent 'Mail::DMARC::Base';

sub save_author {
    my ($self,$meta,$policy,$records) = @_;
# Reports that others generate, when they receive email purporting to be us

    my %required = (
        meta    => [ qw/ domain org_name email begin end report_id / ],
        policy  => [ qw/  / ],
        records => [ qw/  / ],
    );
#warn Dumper($meta); ## no critic (Carp)
    foreach my $k ( keys %required ) {
        foreach my $f ( @{ $required{$k} } ) {
            croak "missing $k, $f" if 'policy'  eq $k && ! $policy->{$f};
            croak "missing $k, $f" if 'meta'    eq $k && ! $meta->$f;
            croak "missing $k, $f" if 'records' eq $k && ! $records->{$f};
        };
    };

    my $rid = $self->insert_author_report($meta,$policy) or croak "failed to create report!";

    foreach my $rec ( @$records ) {
        next if ! $rec;

        my $row_id = $self->insert_report_row( $rid,
                { map { $_ => $rec->{identifiers}{$_} } qw/ source_ip header_from envelope_to envelope_from / },
                { map { $_ => $rec->{policy_evaluated}{$_} } qw/ disposition dkim spf / },
                ) or croak "failed to insert row";

# TODO
        my $reason = $rec->{reason};
        if ( $reason && $reason->{type} ) {
            $self->insert_rr_reason($row_id, $reason->{type}, $reason->{comment} );
        };

        my $spf_ref = $rec->{auth_results}{spf};
        if ($spf_ref && scalar @$spf_ref ) {
            foreach my $spf ( @$spf_ref ) {
                $self->insert_rr_spf( $row_id, $spf );
            };
        };

        my $dkim = $rec->{auth_results}{dkim};
        if ( $dkim ) {
            foreach my $sig ( @$dkim ) {
                $self->insert_rr_dkim($row_id, $sig);
            };
        };
    };

    return $self->{report_row_id};
};

sub save_receiver {
    my $self = shift;
# Reports we generate locally, while receiving email
    $self->{dmarc} = shift or croak "missing object with DMARC results\n";
    my $too_many = shift and croak "invalid arguments";

    my $rid = $self->insert_receiver_report or croak "failed to create report!";
    my $row_id = $self->insert_report_row(
            $rid,
            { map { $_ => $self->dmarc->$_ } qw/ source_ip header_from envelope_to envelope_from / },
            $self->dmarc->result,
            ) or croak "failed to insert row";

    my $reason = $self->dmarc->result->reason;
    if ( $reason && $reason->type ) {
        $self->insert_rr_reason($row_id, $reason->type, $reason->comment );
    };

    my $spf = $self->dmarc->spf;
    if ( $spf ) {
        $self->insert_rr_spf( $row_id, $spf );
    };

    my $dkim = $self->dmarc->dkim;
    if ( $dkim ) {
        foreach my $sig ( @$dkim ) {
            $self->insert_rr_dkim($row_id, $sig);
        };
    };

    return $row_id;
};

sub retrieve {
    my ($self, %args) = @_;
    my $query = 'SELECT * FROM report WHERE 1=1';
    my @qparm;
    if ( $args{end} ) {
        $query .= " AND end < ?";
        push @qparm, $args{end};
#       print "query: $query ($args{end})\n";
    };
    my $reports = $self->query( $query, [ @qparm ] );
    foreach my $r ( @$reports ) {
        $r->{policy_published} = $self->query( 'SELECT * from report_policy_published WHERE report_id=?', [ $r->{id} ] )->[0];
        my $rows = $r->{rows} = $self->query( 'SELECT * from report_record WHERE report_id=?', [ $r->{id} ] );
        foreach my $row ( @$rows ) {
            $row->{source_ip} = $self->any_inet_ntop( $row->{source_ip} );
            $row->{reason} = $self->query( 'SELECT type,comment from report_record_reason WHERE report_record_id=?', [ $row->{id} ]);
            $row->{auth_results}{spf} = $self->query( 'SELECT domain,result,scope from report_record_spf WHERE report_record_id=?', [ $row->{id} ] );
            $row->{auth_results}{dkim} = $self->query( 'SELECT domain,selector,result,human_result from report_record_dkim WHERE report_record_id=?', [ $row->{id} ] );
        };
    };
    return $reports;
};

sub delete_report {
    my $self = shift;
    my $report_id = shift or carp "missing report ID";
    print "deleting report $report_id\n";

    # deletes with FK don't cascade in SQLite? Clean each table manually
    my $rows = $self->query( 'SELECT id FROM report_record WHERE report_id=?', [ $report_id ] );
    my $row_ids = join(',', map { $_->{id} } @$rows) or return 1;
    foreach my $table ( qw/ report_record_spf report_record_dkim report_record_reason / ) {
        print "deleting $table rows $row_ids\n";
        $self->query("DELETE FROM $table WHERE report_record_id IN ($row_ids)");
    };
    foreach my $table ( qw/ report_policy_published report_record / ) {
        $self->query("DELETE FROM $table WHERE report_id=?", [ $report_id ] );
    };
# In MySQL, where FK constraints DO cascade, this is the only query needed
    $self->query("DELETE FROM report WHERE id=?", [ $report_id ] );
    return 1;
};

sub dmarc { return $_[0]->{dmarc}; };

sub get_domain_id {
    my ($self, $domain) = @_;
    croak "missing domain calling ".(caller(0))[3] if ! $domain;
    my $r = $self->query('SELECT id FROM domain WHERE domain=?', [$domain]);
    if ( $r && scalar @$r ) {
        return $r->[0]{id};
    };
    return $self->query('INSERT INTO domain (domain) VALUES (?)', [$domain]);
};

sub get_author_id {
    my ($self, $meta) = @_;
    croak "missing author name" if ! $meta->org_name;
    my $r = $self->query('SELECT id FROM author WHERE org_name=?', [$meta->org_name]);
    if ( $r && scalar @$r ) {
        return $r->[0]{id};
    };
    carp "missing email" if ! $meta->email;
    return $self->query('INSERT INTO author (org_name,email,extra_contact) VALUES (??)',
            [ $meta->org_name, $meta->email, $meta->extra_contact_info ]
        );
};

sub insert_rr_reason {
    my ($self,$row_id,$type,$comment) = @_;
    return $self->query( 'INSERT INTO report_record_reason (report_record_id, type, comment) VALUES (?,?,?)',
            [ $row_id, $type, $comment || '' ]
        );
};

sub insert_rr_dkim {
    my ($self,$row_id,$dkim) = @_;

    my $query = <<'EO_DKIM'
INSERT INTO report_record_dkim
    (report_record_id, domain, selector, result, human_result)
VALUES (??)
EO_DKIM
;
    my @dkim_fields = qw/ domain selector result human_result /;
    $self->query( $query, [ $row_id, map { $dkim->{$_} } @dkim_fields ] );
    return 1;
};

sub insert_rr_spf {
    my ($self,$row_id,$spf) = @_;
    my $r = $self->query(
'INSERT INTO report_record_spf (report_record_id, domain, scope, result) VALUES(??)',
            [ $row_id, $spf->{domain}, $spf->{scope}, $spf->{result}, ]
        ) or croak "failed to insert SPF";
    return $r;
};

sub insert_report_row {
    my ($self,$report_id,$identifiers,$result) = @_;
    $report_id or croak "report ID required?!";
    my $query = <<'EO_ROW_INSERT'
INSERT INTO report_record
   (report_id, source_ip, header_from, envelope_to, envelope_from,
    disposition, dkim, spf
    )
   VALUES (??)
EO_ROW_INSERT
;
    my $args = [
        $report_id,
        (map { $identifiers->{$_} || '' } qw/ source_ip header_from envelope_to envelope_from /),
        (map { $result->{$_} } qw/ disposition dkim spf /),
        ];
    my $row_id = $self->query( $query, $args ) or croak;
    return $self->{report_row_id} = $row_id;
};

sub insert_author_report {
    my ($self, $meta, $pub_pol) = @_;

# check if report exists
    my $rcpt_dom_id = $self->get_domain_id( $meta->domain );
    my $author_id   = $self->get_author_id( $meta );
    my $from_dom_id = $self->get_domain_id( $pub_pol->domain );

    my $ids = $self->query(
        'SELECT id FROM report WHERE rcpt_domain_id=? AND uuid=? AND author_id=?',
        [ $rcpt_dom_id, $meta->report_id, $author_id ]
        );

    if ( scalar @$ids ) {
#       warn "found " . scalar @$ids . " matching reports!";
        return $self->{report_id} = $ids->[0]{id};
    }

# report for this author_domain does not exist, insert new
    my $rid = $self->{report_id} = $self->query(
        'INSERT INTO report (from_domain_id, rcpt_domain_id, begin, end, author_id) VALUES (??)',
        [ $from_dom_id, $rcpt_dom_id, $meta->begin, $meta->end, $author_id ]
    ) or return;

    $self->insert_report_published_policy($rid,$pub_pol);
    return $rid;
};

sub insert_receiver_report {
    my $self = shift;

    my $from_id = $self->get_domain_id($self->dmarc->header_from) or croak "missing header_from!";
    my $rcpt_id = $self->get_domain_id($self->dmarc->envelope_to);
    my $meta = $self->dmarc->report->meta;
    $meta->org_name( $self->config->{organization}{org_name} );
    my $author_id = $self->get_author_id( $meta );

    my $ids = $self->query(
        'SELECT id FROM report WHERE from_domain_id=? AND end > ?',
        [ $from_id, time ]
        );

    if ( scalar @$ids ) {
#       warn "found " . scalar @$ids . " matching reports!";
        return $self->{report_id} = $ids->[0]{id};
    }

# report for this author_domain does not exist, insert new
    my $pub = $self->dmarc->result->published or croak "unable to get published policy";
    my $rid = $self->{report_id} = $self->query(
        'INSERT INTO report (author_id, from_domain_id, rcpt_domain_id, begin, end) VALUES (??)',
        [ $author_id, $from_id, $rcpt_id, time, time + ($pub->ri || 86400) ]
    ) or return;

    $pub->apply_defaults or croak "failed to apply policy defaults?!";
    $self->insert_report_published_policy($rid,$pub);
    return $rid;
};

sub insert_report_published_policy {
    my ($self,$id,$pub) = @_;
    my $query = 'INSERT INTO report_policy_published (report_id, adkim, aspf, p, sp, pct, rua) VALUES (?,?,?,?,?,?,?)';
    return $self->query( $query, [
            $id,
            $pub->{adkim}, $pub->{aspf},
            $pub->{p},     $pub->{sp},
            $pub->{pct},   $pub->{rua},
            ]
            ) or croak "failed to insert published policy";
};

sub db_connect {
    my $self = shift;

    return $self->{dbh} if $self->{dbh};   # caching

    my $dsn  = $self->config->{report_store}{dsn} or croak;
    my $user = $self->config->{report_store}{user};
    my $pass = $self->config->{report_store}{pass};

    my $needs_tables;
    if ( $dsn =~ /sqlite/i ) {
        my ($db) = (split /=/, $dsn)[-1];
        if ( ! $db || $db eq ':memory:' || ! -e $db ) {
            my $schema = 'mail_dmarc_schema.sqlite';
            $needs_tables = $self->get_db_schema($schema) or
                croak "can't locate DB $db AND can't find $schema! Create $db manually.\n";
        };
    };

    $self->{dbh} = DBIx::Simple->connect( $dsn, $user, $pass )
        or return $self->error( DBIx::Simple->error );

    if ( $needs_tables ) {
        $self->apply_db_schema($needs_tables);
    };
    return $self->{dbh};
};

sub apply_db_schema {
    my ($self, $file) = @_;
    my $setup = $self->slurp($file);
    foreach ( split /;/, $setup ) { $self->{dbh}->query($_); };
    return;
};

sub get_db_schema {
    my ($self, $file) = @_;
    return "share/$file" if -f "share/$file";              # when testing
    return File::ShareDir::dist_file('Mail-DMARC', $file); # when installed
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
