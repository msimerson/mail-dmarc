package Mail::DMARC::Report::Aggregate::Metadata;
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

our $VERSION = '2.20260621';

use XML::LibXML;

use parent 'Mail::DMARC::Base';

sub org_name( $self, $value = undef ) {
    return $self->{org_name} if @_ == 1;
    return $self->{org_name} = $value;
}

sub email( $self, $value = undef ) {
    return $self->{email} if @_ == 1;
    return $self->{email} = $value;
}

sub extra_contact_info( $self, $value = undef ) {
    return $self->{extra_contact_info} if @_ == 1;
    return $self->{extra_contact_info} = $value;
}

sub report_id( $self, $value = undef ) {
    return $self->{report_id} if @_ == 1;
    return $self->{report_id} = $value;
}

sub date_range( $self, $value = undef ) {
    return $self->{date_range} if @_ == 1;

    #   croak "invalid date_range" if ('HASH' ne ref $value);
    return $self->{date_range} = $value;
}

sub begin( $self, $value = undef ) {
    return $self->{date_range}{begin} if @_ == 1;
    return $self->{date_range}{begin} = $value;
}

sub end( $self, $value = undef ) {
    return $self->{date_range}{end} if @_ == 1;
    return $self->{date_range}{end} = $value;
}

sub error( $self, $value = undef ) {
    return $self->{error} if @_ == 1;
    return push @{ $self->{error} }, $value;
}

sub uuid( $self, $value = undef ) {
    return $self->{uuid} if @_ == 1;
    return $self->{uuid} = $value;
}

sub as_xml($self) {
    my $meta = "\t<report_metadata>\n";

    foreach my $f (qw/ org_name email extra_contact_info report_id /) {
        my $val = $self->$f or next;
        $val = XML::LibXML::Text->new($val)->toString();
        $meta .= "\t\t<$f>$val</$f>\n";
    }
    my $begin = XML::LibXML::Text->new( $self->begin )->toString();
    my $end   = XML::LibXML::Text->new( $self->end )->toString();
    $meta
        .= "\t\t<date_range>\n\t\t\t<begin>"
        . $begin
        . "</begin>\n"
        . "\t\t\t<end>"
        . $end
        . "</end>\n\t\t</date_range>\n";

    my $errors = $self->error;
    if ( $errors && @$errors ) {
        foreach my $err (@$errors) {
            $err = XML::LibXML::Text->new($err)->toString();
            $meta .= "\t\t<error>$err</error>\n";
        }
    }
    $meta .= "\t</report_metadata>";
    return $meta;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Metadata - metadata section of aggregate report

=head1 VERSION

version 2.20260621

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
