package Mail::DMARC::Report::Aggregate::Record;
our $VERSION = '1.20230215';
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC::Base';
require Mail::DMARC::Report::Aggregate::Record::Identifiers;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results;
require Mail::DMARC::Report::Aggregate::Record::Row;

sub new {
    my ( $class, @args ) = @_;
    croak "invalid arguments" if @args % 2;

    my $self = bless {}, $class;
    return $self if 0 == scalar @args;

    my %args = @args;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }

    return $self;
}

sub identifiers {
    my ($self, @args) = @_;

    if ( !scalar @args ) {
        return $self->{identifiers} if $self->{identifiers};
    }

    if ('HASH' eq ref $args[0]) {
        @args = %{ $args[0] };
    }

    return $self->{identifiers} =
        Mail::DMARC::Report::Aggregate::Record::Identifiers->new(@args);
}

sub auth_results {
    my ($self, @args) = @_;

    if ( !scalar @args ) {
        return $self->{auth_results} if $self->{auth_results};
    }

    if ( 1 == scalar @args && 'HASH' eq ref $args[0] ) {
        @args = %{ $args[0] };
    }

    return $self->{auth_results} =
        Mail::DMARC::Report::Aggregate::Record::Auth_Results->new(@args);
}

sub row {
    my ($self, @args) = @_;

    if ( 0 == scalar @args ) {
        return $self->{row} if $self->{row};
    }

    if ( 1 == scalar @args && 'HASH' eq ref $args[0] ) {
        @args = %{ $args[0] };
    }

    return $self->{row} =
        Mail::DMARC::Report::Aggregate::Record::Row->new(@args);
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record - record section of aggregate report

=head1 VERSION

version 1.20230215

=head1 DESCRIPTION

An aggregate report record, with object methods for identifiers, auth_results, and each row.

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

This software is copyright (c) 2024 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
