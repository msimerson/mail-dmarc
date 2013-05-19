package Mail::DMARC::Report::Receive;
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
    eval "require Net::IMAP::Simple"; ## no critic (Eval)
    croak "Net::IMAP::Simple seems to not work, is it installed?" if $@;

    my $server = $self->config->{imap}{server} or croak "missing imap server setting";
    my $folder = $self->config->{imap}{folder} or croak "missing imap folder setting";
    my $a_done = $self->config->{imap}{a_done} or croak "missing imap a_done setting";
    my $f_done = $self->config->{imap}{f_done} or croak "missing imap f_done setting";

    no warnings qw(once); ## no critic (Warn)
    my $imap = Net::IMAP::Simple->new($server, Port => 995, use_ssl => 1 )
        or croak "Unable to connect to IMAP: $Net::IMAP::Simple::SSL::errstr\n";

    $imap->login( $self->config->{imap}{user}, $self->config->{imap}{pass} )
        or croak "Login failed: " . $imap->errstr . "\n";

    my $nm = $imap->select( $self->config->{imap}{folder} );
    $imap->expunge_mailbox( $self->config->{imap}{folder} );
    my @mess = $imap->search('SEEN', 'DATE');

#   for(my $i = 1; $i <= $nm; $i++){
    foreach my $i ( @mess ) {
        print $imap->seen($i) ? '*' : ' ';
        printf "[%03d] ", $i;
        my $message = $imap->get($i) or do {
            carp "unable to get message $i\n";
            next;
        };
        my $type = $self->from_email_simple( Email::Simple->new( "$message" ) );
        next if ! $type;
        my $done_box = $type eq 'aggregate' ? $a_done
                     : $type eq 'forensic'  ? $f_done
                     : croak "unknown type!";

        $imap->copy( $i, $done_box ) or do {
            warn $imap->errstr;
            next;
        };
        $imap->delete( $i );
    }

    $imap->quit;
    return 1;
};

sub from_file {
    my ($self, $file) = @_;
    croak "missing message!" if ! $file;
    croak "No such file $file: $!" if ! -f $file;
    return $self->from_email_simple( Email::Simple->new( $self->slurp( $file ) ));
};

sub from_email_simple {
    my ($self, $email) = @_;

    $self->report->init();
    $self->get_submitter_from_subject( $email->header('Subject') );

    my $unzipper = { gz  => \&IO::Uncompress::Gunzip::gunzip,  # 2013 draft
                     zip => \&IO::Uncompress::Unzip::unzip,    # legacy format
                   };

    my $rep_type;
    foreach my $part ( Email::MIME->new($email->as_string)->parts ) {
        my ($c_type) = split /;/, $part->content_type;
        next if $c_type eq 'text/plain';
        if ( $c_type eq 'text/rfc822-headers' ) {
            carp "TODO: handle forensic reports\n";
            $rep_type = 'forensic';
            next;
        };
        if ( $c_type eq 'message/feedback-report' ) {
            carp "TODO: handle forensic reports\n";
            $rep_type = 'forensic';
            next;
        };
        my $bigger;
        if ( $c_type eq 'application/zip' || $c_type eq 'application/x-zip-compressed' ) {
            $self->get_submitter_from_filename( $part->{ct}{attributes}{name} );
            $unzipper->{zip}->( \$part->body, \$bigger );
            $self->handle_body( $bigger );
            $rep_type = 'aggregate';
            next;
        };
        if ( $c_type eq 'application/gzip' ) {
            $self->get_submitter_from_filename( $part->{ct}{attributes}{name} );
            $unzipper->{gz}->( \$part->body, \$bigger );
            $self->handle_body( $bigger );
            $rep_type = 'aggregate';
            next;
        };
        carp "What is type $c_type doing in here?\n";
    };
    return $rep_type;
};

sub get_submitter_from_filename {
    my ($self, $filename ) = @_;
    return if $self->report->meta->domain;
    my ($submitter_dom, $report_dom, $begin, $end) = split /!/, $filename;
    return $self->report->meta->domain( $submitter_dom ) if $submitter_dom;
};

sub get_submitter_from_subject {
    my ($self, $subject ) = @_;
# The 2013 DMARC spec section 12.2.1 suggests that the header SHOULD conform
# to a supplied ABNF. Rather than "require" such conformance, this method is
# more concerned with reliably extracting the submitter domain. Quickly.
    $subject = lc Encode::decode('MIME-Header', $subject );
    print $subject . "\n";
    $subject = substr($subject, 8) if 'subject:' eq substr($subject,0,8);
    $subject =~ s/(?:report\sdomain|submitter|report-id)//gx; # remove keywords
    $subject =~ s/\s+//g;  # remove white space
    my (undef, $report_dom, $submitter_dom, $report_id) = split /:/, $subject;
    $self->report->meta->uuid( $report_id );
    return $self->report->meta->domain( $submitter_dom );
};

sub handle_body {
    my ($self, $body) = @_;
#   print "handling decompressed body\n";

    my $dom = XML::LibXML->load_xml( string => $body );
    foreach my $top ( qw/ report_metadata policy_published / ) {
        my $sub = 'handle_node_' . $top;
        $self->$sub( $dom->findnodes("/feedback/$top") );
    };

    foreach my $record ( $dom->findnodes("/feedback/record" ) ) {
        $self->handle_node_record( $record );
    };

    return $self->report->save_author();
};

sub report {
    my $self = shift;
    return $self->{report} if ref $self->{report};
    return $self->{report} = Mail::DMARC::Report->new();
};

sub handle_node_report_metadata {
    my ($self, $node) = @_;

    foreach my $n ( qw/ org_name email extra_contact_info report_id / ) {
        $self->report->meta->$n( $node->findnodes("./$n")->string_value );
    };

    foreach my $n ( qw/ begin end / ) {
        $self->report->meta->$n( $node->findnodes("./date_range/$n")->string_value );
    };

    foreach my $n ( $node->findnodes("./error") ) {
        $self->report->meta->error( $n->string_value );
    };
    return $self->report->meta;
};

sub handle_node_policy_published {
    my ($self, $node) = @_;

    my $pol = Mail::DMARC::Policy->new();

    foreach my $n ( qw/ domain adkim aspf p sp pct / ) {
        my $val = $node->findnodes("./$n")->string_value or next;
        $val =~ s/\s*//g;  # remove whitespace
        $pol->$n( $val );
    };

    $self->report->policy_published( $pol );
    return $pol;
};

sub handle_node_record {
    my ($self, $node) = @_;

    my $row;
    my %auth = (
        dkim => [ qw/ domain selector result human_result / ],
        spf  => [ qw/ domain scope result / ],
    );

#auth_results: dkim, spf
    foreach my $a ( keys %auth ) {
        foreach my $n ( $node->findnodes("./auth_results/$a" ) ) {
            push @{ $row->{auth_results}{$a} }, {
                map { $_ => $node->findnodes("./auth_results/$a/$_")->string_value } @{ $auth{$a} }
            };
        };
    };

    $row->{identifiers}{source_ip} =
        $node->findnodes("./row/source_ip")->string_value;

    $row->{count} = $node->findnodes("./row/count")->string_value;

#row: policy_evaluated
    foreach my $pe ( qw/ disposition dkim spf / ) {
        $row->{policy_evaluated}{$pe} = $node->findnodes("./row/policy_evaluated/$pe")->string_value;
    };

#reason
    foreach my $r ( $node->findnodes("./row/policy_evaluated/reason" ) ) {
        push @{ $row->{policy_evaluated}{reason} }, $r->string_value;
    };

#identifiers:
    foreach my $i ( qw/ envelope_to envelope_from header_from / ) {
        $row->{identifiers}{$i} = $node->findnodes("./identifiers/$i")->string_value;
    };

    $self->report->add_record($row);
    return $row;
};

1;
__END__
# ABSTRACT: process incoming DMARC reports
sub {}

=head1 DESCRIPTION

Receive DMARC reports, via SMTP or HTTP.

=head1 Report Receiver

=head2 HTTP

=head2 SMTP


=cut
