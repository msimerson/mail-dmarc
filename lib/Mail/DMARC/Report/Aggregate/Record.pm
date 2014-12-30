package Mail::DMARC::Report::Aggregate::Record;
our $VERSION = '1.20141230'; # VERSION
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC::Base';

sub identifiers {
    my ($self, @args) = @_;
    return $self->{identifiers} if ! scalar @args;
    croak "missing identifier"  if ! $args[0];
    my %id = 1 == scalar @args ? %{ $args[0] }
           : scalar @args % 2 == 0 ? @args
           : croak "identifiers is required!";

    croak "identifiers/header_from is required!" if ! $id{header_from};
    if ( ! $id{envelope_from} && $self->verbose ) {
        warn "\tidentifiers/envelope_from is missing!\n"; ## no critic (Carp)
    };
    return $self->{identifiers} = \%id;
}

sub auth_results {
    my ($self, @args) = @_;
    return $self->{auth_results} if ! scalar @args;
    my %auth = (1 == scalar @args) ? %{ $args[0] }
           : (scalar @args % 2 == 0) ? @args
           : croak "auth_results is required!";

    croak "auth_results/spf is required!" if ! $auth{spf};
    if ( ! $auth{dkim} && $self->verbose ) {
        warn  "\tauth_results/dkim is missing\n"; ## no critic (Carp)
    };
    return $self->{auth_results} = \%auth;
}

sub row {
    my ($self, @args) = @_;
    return $self->{row} if ! scalar @args;
    croak "invalid row value!" if ! $args[0];
    my %row = 1 == scalar @args     ? %{ $args[0] }
            : 0 == scalar @args % 2 ? @args
            : croak "row is required!";

    croak "row/source_ip is required!" if ! $row{source_ip};
    croak "row/policy_evaluated is missing!" if ! $row{policy_evaluated};
    if ( ! $row{count} && $self->verbose ) {
        warn "\trow/count is missing!";  ## no critic (Carp)
    };

    return $self->{row} = \%row;
}

1;
# ABSTRACT: record section of aggregate report

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record - record section of aggregate report

=head1 VERSION

version 1.20141230

=head1 DESCRIPTION

An aggregate report record, with object methods for identifiers, auth_results, and each row.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

__END__
sub {}

