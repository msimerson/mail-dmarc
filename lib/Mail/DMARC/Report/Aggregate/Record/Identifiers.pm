package Mail::DMARC::Report::Aggregate::Record::Identifiers;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;

sub new( $class, @args ) {
    croak "invalid arguments" if @args % 2;
    my %args = @args;
    my $self = bless {}, $class;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }
    return $self;
}

sub envelope_to( $self, $value = undef ) {
    return $self->{envelope_to} if @_ == 1;
    return $self->{envelope_to} = $value;
}

sub envelope_from( $self, $value = undef ) {
    return $self->{envelope_from} if @_ == 1;
    return $self->{envelope_from} = $value;
}

sub header_from( $self, $value = undef ) {
    return $self->{header_from} if @_ == 1;
    return $self->{header_from} = $value;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Identifiers - identifiers section of a DMARC aggregate record

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
