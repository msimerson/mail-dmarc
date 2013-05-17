package Mail::DMARC::Report::Receive;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Email::MIME;
use IO::Uncompress::Unzip;
use IO::Uncompress::Gunzip;
use XML::LibXML::Reader;

use parent 'Mail::DMARC::Base';

sub from_email_msg {
    my ($self, $msg) = @_;

    croak "missing message!" if ! $msg;
    if ( $msg !~ /\n/ ) {  # a filename
        croak "What is $msg?" if ! -f $msg;
        $msg = $self->slurp( $msg );
    };

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

sub handle_body {
    my ($self, $body) = @_;
    print "handling decompressed body\n";

    my $reader = XML::LibXML::Reader->new( string => $body );
    while ($reader->read) {
        $self->processNode($reader);
    }

    return $self->save_report();
};

sub save_report {
    my $self = shift;
    print Dumper $self->{_report};
    return;

#   return $self->store->backend->save_author();
};

sub processNode {
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
        my $ip = $self->{_cur_ip};
        my $index = scalar keys %{ $self->{_ips_list} } || 0;

        if ( $tag2 eq 'source_ip' ) {
# if we had to parse REALLY big files with lots of records, this would be
# a good place to commit previous records to the DB and delete them
            $ip = $self->{_cur_ip} = $reader->value;
            $self->{_ips_list}{$ip} = 1;
            $self->{_report}{$tag0}[$index+1]{identifiers}{source_ip} = $ip;
            return;
        };

        if ( $tag2 && $tag2 eq 'count' ) {
            $self->{_report}{$tag0}[$index]{$tag2} = $reader->value;
            return;
        };

        if ( $tag1 eq 'identifiers' ) {
            $self->{_report}{$tag0}[$index]{$tag1}{$tag2} = $reader->value;
            return;
        };
        if ( $tag1 eq 'auth_results' ) {
            $self->{_report}{$tag0}[$index]{$tag1}{$tag2}{$tag3} = $reader->value;
            return;
        };
        if ( $tag1 eq 'row' && $tag2 eq 'policy_evaluated' ) {
            $self->{_report}{$tag0}[$index]{$tag2}{$tag3} = $reader->value;
            return;
        };
    };

    print "0: $tag0, 1: $tag1, 2: $tag2, 3: $tag3\n";
    printf "%d %s\n", ($reader->depth, $reader->name );
    croak "unrecognized tags";
}


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
