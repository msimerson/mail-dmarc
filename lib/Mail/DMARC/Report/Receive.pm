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
use XML::LibXML::Reader;

use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Store;

sub from_email_msg {
    my ($self, $msg) = @_;

    $self->init();

    croak "missing message!" if ! $msg;
    if ( $msg !~ /\n/ ) {  # a filename
        croak "What is $msg?" if ! -f $msg;
        $msg = $self->slurp( $msg );
    };

    my $email = Email::Simple->new($msg);
    $self->get_submitter_from_subject( $email->header('Subject') );

    my $unzipper = { gz  => \&IO::Uncompress::Gunzip::gunzip,  # 2013 draft
                     zip => \&IO::Uncompress::Unzip::unzip,    # legacy format
                   };

    foreach my $part ( Email::MIME->new($msg)->parts ) {
        my ($type) = split /;/, $part->content_type;
        next if $type eq 'text/plain';
        my $bigger;
        if ( $type eq 'application/zip' || $type eq 'application/x-zip-compressed' ) {
            print "got a zip!\n";
            $unzipper->{zip}->( \$part->body, \$bigger );
            $self->handle_body( $bigger );
            next;
        };
        if ( $type eq 'application/gzip' ) {
            print "got a gzip!\n";
            $unzipper->{gz}->( \$part->body, \$bigger );
            $self->handle_body( $bigger );
            next;
        };
        carp "What is type $type doing in here?\n";
    };
    return 1;
};

sub get_submitter_from_subject {
    my ($self, $subject ) = @_;
# The 2013 DMARC spec section 12.2.1 suggests that the header SHOULD conform
# to a supplied ABNF. Rather than "require" such conformance, this method is
# more concerned with reliably extracting the submitter domain. Quickly.
    $subject = lc Encode::decode('MIME-Header', $$subject );
    $subject = substr($subject, 8) if 'subject:' eq substr($subject,0,8);
    $subject =~ s/(?:report\sdomain|submitter|report-id)//gx; # remove keywords
    $subject =~ s/\s+//g;  # remove white space
    my (undef, $report_dom, $submitter_dom, $report_id) = split /:/, $subject;
    $self->{_report}{report_metadata}{uuid} = $report_id;
    return $self->{_report}{report_metadata}{domain} = $submitter_dom;
};

sub handle_body {
    my ($self, $body) = @_;
    print "handling decompressed body\n";

    my $reader = XML::LibXML::Reader->new( string => $body );
    while ($reader->read) {
        $self->process_xml_node($reader);
    }

    return $self->save_report();
};

sub init {
    my $self;
    foreach ( qw/ _ips_list _report _dkim_idx _spf_idx / ) {
        $self->{$_} = undef;
    };
    return;
};

sub save_report {
    my $self = shift;
    $self->{store} ||= Mail::DMARC::Report::Store->new();
#   croak Dumper $self->{_report};
    return $self->{store}->backend->save_author(
            $self->{_report}{report_metadata},
            $self->{_report}{policy_published},
            $self->{_report}{record},
            );
};

sub process_xml_node {
    my ($self, $reader) = @_;

    return if $reader->isEmptyElement;
    return if ! $reader->hasValue;

    my (undef,$top,$tag0,$tag1,$tag2,$tag3) = split /\//, $reader->nodePath;
    croak "unrecognized XML format ($top)\n" if 'feedback' ne $top;

    if ( $tag0 eq 'report_metadata' ) {
        if ( $tag1 eq 'date_range' ) {
            $self->{_report}{report_metadata}{$tag2} = $reader->value;
            return;
        };
        $self->{_report}{$tag0}{$tag1} = $reader->value;
        return;
    };
    if ( $tag0 eq 'policy_published' ) {
        $self->{_report}{$tag0}{$tag1} = $reader->value;
        return;
    };
    if ( $tag0 eq 'record' ) {
        return $self->process_xml_record($reader);
    };

    print "0: $tag0, 1: $tag1, 2: $tag2, 3: $tag3\n";
    printf "%d %s\n", ($reader->depth, $reader->name );
    croak "unrecognized tags";
}

sub process_xml_record {
    my ($self, $reader) = @_;
    my (undef,$top,$tag0,$tag1,$tag2,$tag3) = split /\//, $reader->nodePath;

    my $value = $reader->value;
    my $ip    = $self->{_cur_ip};
    my $row_index = scalar keys %{ $self->{_ips_list} } || 0;
    my $dkim_idx = $self->{_dkim_idx} || 0;
    my $spf_idx = $self->{_spf_idx} || 0;

    if ( $tag2 eq 'source_ip' ) {
# if we had to parse REALLY big files with lots of records, this would be
# a good place to commit previous records to the DB and delete them
        $ip = $self->{_cur_ip} = $value;
        $self->{_ips_list}{$ip} = 1;
        $self->{_report}{$tag0}[$row_index+1]{identifiers}{source_ip} = $ip;
        return;
    };

    if ( $tag2 && $tag2 eq 'count' ) {
        $self->{_report}{$tag0}[$row_index]{$tag2} = $value;
        return;
    };

    if ( $tag1 eq 'identifiers' ) {
        $self->{_report}{$tag0}[$row_index]{$tag1}{$tag2} = $value;
        return;
    };
    if ( $tag1 eq 'auth_results' ) {
#   // record / row / auth_results / dkim|spf /
        if ( $tag2 eq 'dkim' ) {
            if ( $self->{_report}{$tag0}[$row_index]{$tag1}{dkim}[$dkim_idx]{$tag3} ) {
                $dkim_idx++;
            };
            $self->{_report}{$tag0}[$row_index]{$tag1}{dkim}[$dkim_idx]{$tag3} = $value;
            return;
        };
        if ( $tag2 eq 'spf' ) {
            if ( $self->{_report}{$tag0}[$row_index]{$tag1}{spf}[$spf_idx]{$tag3} ) {
                $dkim_idx++;
            };
            $self->{_report}{$tag0}[$row_index]{$tag1}{spf}[$spf_idx]{$tag3} = $value;
            return;
        };
    };
    if ( $tag1 eq 'row' && $tag2 eq 'policy_evaluated' ) {
        $self->{_report}{$tag0}[$row_index]{$tag2}{$tag3} = $value;
        return;
    };

    croak "unrecognized tags: 0: $tag0, 1: $tag1, 2: $tag2, 3: $tag3\n";
};

1;
# ABSTRACT: receive a DMARC report
__END__
sub {}

=head1 DESCRIPTION

Receive DMARC reports, via SMTP or HTTP.

=head1 Report Receiver

=head2 HTTP

=head2 SMTP


=cut
