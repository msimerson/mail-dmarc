package Mail::DMARC::Report::Receive;
our $VERSION = '1.20140208'; # VERSION
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Email::MIME;
use Email::Simple;
use Encode;
use IO::Uncompress::Unzip;
use IO::Uncompress::Gunzip;
use XML::LibXML;

use parent 'Mail::DMARC::Base';
require Mail::DMARC::Policy;
require Mail::DMARC::Report;

sub from_imap {
    my $self = shift;
    eval "require Net::IMAP::Simple";    ## no critic (Eval)
    croak "Net::IMAP::Simple seems to not work, is it installed?" if $@;

    my $server = $self->config->{imap}{server} or croak "no imap server conf";
    my $folder = $self->config->{imap}{folder} or croak "no imap folder conf";
    my $a_done = $self->config->{imap}{a_done};
    my $f_done = $self->config->{imap}{f_done};
    my $port   = $self->get_imap_port();

    no warnings qw(once);                ## no critic (Warn)
    my $imap = Net::IMAP::Simple->new( $server, Port => $port,
            ($port==993 ? (use_ssl => 1) : ()),
        )
        or do {
## no critic (PackageVar)
            my $err = $port == 143 ? $Net::IMAP::Simple::errstr : $Net::IMAP::Simple::SSL::errstr;
            croak "Unable to connect to IMAP: $err\n";
        };

    print "connected to IMAP server $server:$port\n" if $self->verbose;

    $imap->login( $self->config->{imap}{user}, $self->config->{imap}{pass} )
        or croak "Login failed: " . $imap->errstr . "\n";

    print "\tlogged in\n" if $self->verbose;

    my $nm = $imap->select( $self->config->{imap}{folder} );
    $imap->expunge_mailbox( $self->config->{imap}{folder} );
    my @mess = $imap->search( 'UNSEEN', 'DATE' );

    print "\tfound " . scalar @mess . " messages\n" if $self->verbose;

    foreach my $i (@mess) {
        print $imap->seen($i) ? '*' : ' ';
        printf "[%03d] ", $i;
        my $message = $imap->get($i) or do {
            carp "unable to get message $i\n";
            next;
        };
        my $type = $self->from_email_simple( Email::Simple->new("$message") );
        next if !$type;
        my $done_box
            = $type eq 'aggregate' ? $a_done
            : $type eq 'forensic'  ? $f_done
            :                        croak "unknown type!";

        $imap->add_flags( $i, '\Seen' );
        if ( $done_box ) {
            $imap->copy( $i, $done_box ) or do {
                carp $imap->errstr;
                next;
            };
            $imap->add_flags( $i, '\Deleted' );
        };
    }

    $imap->quit;
    return 1;
}

sub from_file {
    my ( $self, $file ) = @_;
    croak "missing message" if !$file;
    croak "No such file $file: $!" if !-f $file;
    return $self->from_email_simple(
        Email::Simple->new( $self->slurp($file) ) );
}

sub from_mbox {
    my ( $self, $file_name ) = @_;
    croak "missing mbox file" if !$file_name;

# TODO: replace this module
# commented out due to build test failures
#   eval "require Mail::Mbox::MessageParser";    ## no critic (Eval)
#   croak "is Mail::Mbox::MessageParser installed?" if $@;

#   my $file_handle = FileHandle->new($file_name);

    my $folder_reader; #  = Mail::Mbox::MessageParser->new(
#       {   'file_name'    => $file_name,
#           'file_handle'  => $file_handle,
#           'enable_cache' => 1,
#           'enable_grep'  => 1,
#       }
#   );

    croak $folder_reader unless ref $folder_reader;

    my $prologue = $folder_reader->prologue;
    print $prologue;

    while ( !$folder_reader->end_of_file() ) {
        $self->from_email_simple(
            Email::Simple->new( $folder_reader->read_next_email() ) );
    }
    return 1;
}

sub from_email_simple {
    my ( $self, $email ) = @_;

    $self->report->init();
    $self->{_envelope_to} = undef;
    $self->{_header_from} = undef;
    $self->get_submitter_from_subject( $email->header('Subject') );

    my $unzipper = {
        gz  => \&IO::Uncompress::Gunzip::gunzip,    # 2013 draft
        zip => \&IO::Uncompress::Unzip::unzip,      # legacy format
    };

    my $rep_type;
    foreach my $part ( Email::MIME->new( $email->as_string )->parts ) {
        my ($c_type) = split /;/, $part->content_type;
        next if $c_type eq 'text/plain';
        if ( $c_type eq 'text/rfc822-headers' ) {
            warn "TODO: handle forensic reports\n";  ## no critic (Carp)
            $rep_type = 'forensic';
            next;
        }
        if ( $c_type eq 'message/feedback-report' ) {
            warn "TODO: handle forensic reports\n";  ## no critic (Carp)
            $rep_type = 'forensic';
            next;
        }
        my $bigger;
        if (   $c_type eq 'application/zip'
            || $c_type eq 'application/x-zip-compressed' )
        {
            $self->get_submitter_from_filename( $part->{ct}{attributes}{name} );
            $unzipper->{zip}->( \$part->body, \$bigger );
            $self->handle_body($bigger);
            $rep_type = 'aggregate';
            next;
        }
        if ( $c_type eq 'application/gzip' ) {
            $self->get_submitter_from_filename( $part->{ct}{attributes}{name} );
            $unzipper->{gz}->( \$part->body, \$bigger );
            $self->handle_body($bigger);
            $rep_type = 'aggregate';
            next;
        }
        warn "Unknown message part $c_type\n";  ## no critic (Carp)
    }
    return $rep_type;
}

sub get_imap_port {
    my $self = shift;

    eval "use IO::Socket::SSL";  ## no critic (Eval)
    if ( $@ ) {
        carp "no SSL, using insecure connection: $!\n";
        return 143;
    };

    eval "use Mozilla::CA";    ## no critic (Eval)
    if ( ! $@ ) {
        IO::Socket::SSL::set_ctx_defaults(
                SSL_verifycn_scheme => 'imap',
                SSL_verify_mode => 0x02,
                SSL_ca_file => Mozilla::CA::SSL_ca_file(),
                );
        return 993;
    };

# no CA, disable verification
    IO::Socket::SSL::set_ctx_defaults(
        SSL_verifycn_scheme => 'imap',
        SSL_verify_mode => 0,
    );
    return 993;
};

sub get_submitter_from_filename {
    my ( $self, $filename ) = @_;
    return if $self->{_envelope_to};  # already parsed from Subject:
    my ( $submitter_dom, $report_dom, $begin, $end ) = split /!/, $filename;
    $self->{_header_from} ||= $report_dom;
    return $self->{_envelope_to} = $submitter_dom;
}

sub get_submitter_from_subject {
    my ( $self, $subject ) = @_;

  # The 2013 DMARC spec section 12.2.1 suggests that the header SHOULD conform
  # to a supplied ABNF. Rather than "require" such conformance, this method is
  # more concerned with reliably extracting the submitter domain. Quickly.
    $subject = lc Encode::decode( 'MIME-Header', $subject );
    print $subject . "\n";
    $subject = substr( $subject, 8 ) if 'subject:' eq substr( $subject, 0, 8 );
    $subject =~ s/(?:report\sdomain|submitter|report-id)//gx; # strip keywords
    $subject =~ s/\s+//g;    # remove white space
    my ( undef, $report_dom, $sub_dom, $report_id ) = split /:/, $subject;
    my $meta = $self->report->aggregate->metadata;
    if ( $report_id && !$meta->uuid ) {
        # remove <containment brackets> if present
        $report_id = substr($report_id,1) if '<' eq substr($report_id,0,1);
        chop $report_id if '>' eq substr($report_id,-1,1);
        $meta->uuid($report_id);
    };
    $self->{_header_from} ||= $report_dom;
    return $self->{_envelope_to} = $sub_dom;
}

sub handle_body {
    my ( $self, $body ) = @_;

    print "handling decompressed body\n" if $self->{verbose};

    my $dom = XML::LibXML->load_xml( string => $body );
    $self->do_node_report_metadata( $dom->findnodes("/feedback/report_metadata") );
    $self->do_node_policy_published( $dom->findnodes("/feedback/policy_published") );

    foreach my $record ( $dom->findnodes("/feedback/record") ) {
        $self->do_node_record($record);
    }

    return $self->report->save_aggregate();
}

sub report {
    my $self = shift;
    return $self->{report} if ref $self->{report};
    return $self->{report} = Mail::DMARC::Report->new();
}

sub do_node_report_metadata {
    my ( $self, $node ) = @_;

    foreach my $n (qw/ org_name email extra_contact_info /) {
        $self->report->aggregate->metadata->$n(
            $node->findnodes("./$n")->string_value );
    }

    my $rid = $node->findnodes("./report_id")->string_value;
    $rid = substr($rid,1) if '<' eq substr($rid,0,1); # remove <
    chop $rid if '>' eq substr($rid,-1,1);            # remove >
    $self->report->aggregate->metadata->report_id( $rid );

    if ( ! $self->report->aggregate->metadata->uuid ) {
        $self->report->aggregate->metadata->uuid( $rid );
    };

    foreach my $n (qw/ begin end /) {
        $self->report->aggregate->metadata->$n(
            $node->findnodes("./date_range/$n")->string_value );
    }

    foreach my $n ( $node->findnodes("./error") ) {
        $self->report->aggregate->metadata->error( $n->string_value );
    }
    return $self->report->aggregate->metadata;
}

sub do_node_policy_published {
    my ( $self, $node ) = @_;

    my $pol = Mail::DMARC::Policy->new();

    foreach my $n (qw/ domain adkim aspf p sp pct /) {
        my $val = $node->findnodes("./$n")->string_value or next;
        $val =~ s/\s*//g;    # remove whitespace
        $pol->$n($val);
    }

    $self->report->aggregate->policy_published($pol);
    return $pol;
}

sub do_node_record {
    my ( $self, $node ) = @_;

    my $rec;
    $self->do_node_record_auth(\$rec, $node);

    foreach my $row (qw/ source_ip count /) {
        $rec->{row}{$row} = $node->findnodes("./row/$row")->string_value;
    };

    # policy_evaluated
    foreach my $pe (qw/ disposition dkim spf /) {
        $rec->{row}{policy_evaluated}{$pe}
            = $node->findnodes("./row/policy_evaluated/$pe")->string_value;
    }

    # reason
    $self->do_node_record_reason( \$rec, $node );

    # identifiers
    foreach my $i (qw/ envelope_to envelope_from header_from /) {
        $rec->{identifiers}{$i}
            = $node->findnodes("./identifiers/$i")->string_value;
    }

# for reports from junc.org with mis-labeled identifiers
    if ( ! $rec->{identifiers}{header_from} ) {
        $rec->{identifiers}{header_from}
            = $node->findnodes("./identities/header_from")->string_value;
    };

# last resort...
    $rec->{identifiers}{envelope_to} ||= $self->{_envelope_to};
    $rec->{identifiers}{header_from} ||= $self->{_header_from};

    $self->report->aggregate->record($rec);
    return $rec;
}

sub do_node_record_auth {
    my ($self, $row, $node) = @_;

    my @dkim = qw/ domain selector result human_result /,
    my @spf  = qw/ domain scope result /;

    foreach ( $node->findnodes("./auth_results/spf") ) {
        my %spf = map { $_ => $node->findnodes("./auth_results/spf/$_")->string_value } @spf;

        if ( $spf{scope} && ! $self->is_valid_spf_scope( $spf{scope} ) ) {
            carp "invalid scope: $spf{scope}, ignoring";
            delete $spf{scope};
        };
# this is for reports from ivenue.com with result=unknown
        if ( $spf{result} && ! $self->is_valid_spf_result( $spf{result} ) ) {
            carp "invalid SPF result: $spf{result}, setting to temperror";
            $spf{result} = 'temperror';
        };
        push @{ $$row->{auth_results}{spf} }, \%spf;
    };

    foreach ( $node->findnodes("./auth_results/dkim") ) {
        push @{ $$row->{auth_results}{dkim} }, {
            map { $_ => $node->findnodes("./auth_results/dkim/$_")->string_value } @dkim
        };
    };

    return;
};

sub do_node_record_reason {
    my ($self, $row, $node) = @_;

    my @types = qw/ forwarded sampled_out trusted_forwarder mailing_list
                    local_policy other /;
    my %types = map { $_ => 1 } @types;

    foreach my $r ( $node->findnodes("./row/policy_evaluated/reason") ) {
        my $type = $r->findnodes('./type')->string_value or next;
        my $comment = $r->findnodes('./comment')->string_value;
        push @{ $$row->{policy_evaluated}{reason} }, {
            type    => $type,
            comment => $comment,
        };
    }
    return;
};

1;

=pod

=head1 NAME

Mail::DMARC::Report::Receive - process incoming DMARC reports

=head1 VERSION

version 1.20140208

=head1 DESCRIPTION

Receive DMARC reports and save them to the report store/database.

=head1 METHODS

=head2 from_imap, from_file, from_mbox

These methods are called by L<dmarc_receive> program, which has its own documentation and usage instructions. The methods accept a message (or list of messages) and create an Email::Simple object from each, passing that object to from_email_simple.

=head2 from_email_simple

Accepts an Email::Simple message object. Returns the type of DMARC report detected or undef if no DMARC report was detected.

When forensic reports are detected, no further processing is done.

When an aggregate report is detected, the report details are extracted from the message body as well as the Subject field/header and attachment metadata.

Parsing of the Subject and MIME metadata is necessary because the 2013 draft DMARC specification does not REQUIRE the envelope_to domain name to be included in the XML report. For example, the only way to B<know> that the email which generated this particular report was sent to hotmail.com is to extract the envelope_to domain from the message metadata (Org Name=Microsoft, hotmail.com is not in the XML). So far, every messsage I have seen has had the envelope_to domain in one location or the other.

To extract messages from the message body, the MIME attachments are decompressed and passed to L<handle_body>.

=head2 handle_body

Accepts a XML message, parsing it with XML::LibXML and XPath expressions. The parsed data is stored in a L<Mail::DMARC::Report> object. When the parsing is complete, the report object is saved to the report store.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by ColocateUSA.com.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

__END__
# ABSTRACT: process incoming DMARC reports
sub {}

