package Mail::DMARC::Report::Aggregate::Metadata;
our $VERSION = '1.20130604'; # VERSION
use strict;
use warnings;

use parent 'Mail::DMARC::Base';

sub org_name {
    return $_[0]->{org_name} if 1 == scalar @_;
    return $_[0]->{org_name} = $_[1];
}

sub email {
    return $_[0]->{email} if 1 == scalar @_;
    return $_[0]->{email} = $_[1];
}

sub extra_contact_info {
    return $_[0]->{extra_contact_info} if 1 == scalar @_;
    return $_[0]->{extra_contact_info} = $_[1];
}

sub report_id {
    return $_[0]->{report_id} if 1 == scalar @_;
    return $_[0]->{report_id} = $_[1];
}

sub date_range {
    return $_[0]->{date_range} if 1 == scalar @_;

    #   croak "invalid date_range" if ('HASH' ne ref $_->[1]);
    return $_[0]->{date_range} = $_[1];
}

sub begin {
    return $_[0]->{date_range}{begin} if 1 == scalar @_;
    return $_[0]->{date_range}{begin} = $_[1];
}

sub end {
    return $_[0]->{date_range}{end} if 1 == scalar @_;
    return $_[0]->{date_range}{end} = $_[1];
}

sub error {
    return $_[0]->{error} if 1 == scalar @_;
    return push @{ $_[0]->{error} }, $_[1];
}

sub uuid {
    return $_[0]->{uuid} if 1 == scalar @_;
    return $_[0]->{uuid} = $_[1];
}

sub as_xml {
    my $self = shift;
    my $meta = "\t<report_metadata>\n\t\t<report_id>"
             . $self->report_id . "</report_id>\n";

    foreach my $f (qw/ org_name email extra_contact_info /) {
        my $val = $self->$f or next;
        $meta .= "\t\t<$f>$val</$f>\n";
    }
    $meta .= "\t\t<date_range>\n\t\t\t<begin>" . $self->begin . "</begin>\n"
          .  "\t\t\t<end>" . $self->end . "</end>\n\t\t</date_range>\n";

    my $errors = $self->error;
    if ( $errors && @$errors ) {
        foreach my $err ( @$errors ) {
            $meta .= "\t\t<error>$err</error>\n";
        };
    };
    $meta .= "\t</report_metadata>";
    return $meta;
}

1;
# ABSTRACT: metadata section of aggregate report

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Metadata - metadata section of aggregate report

=head1 VERSION

version 1.20130604

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=back

=head1 CONTRIBUTOR

ColocateUSA.net <company@colocateusa.net>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by ColocateUSA.com.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

__END__
sub {}
