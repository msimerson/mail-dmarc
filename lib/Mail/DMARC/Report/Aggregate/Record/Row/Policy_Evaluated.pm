package Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;

sub new( $class, @args ) {
    croak "invalid arguments" if @args % 2;
    my %args = @args;
    my $self = bless { reason => [] }, $class;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }
    return $self;
}

sub disposition( $self, $value = undef ) {
    return $self->{disposition} if @_ == 1;
    croak 'invalid disposition: ' . ( $value // '(undef)' )
        if !defined $value || 0 == grep {/^$value$/ix} qw/ reject quarantine none /;
    return $self->{disposition} = $value;
}

sub dkim( $self, $value = undef ) {
    return $self->{dkim} if @_ == 1;
    return $self->{dkim} = $value;
}

sub spf( $self, $value = undef ) {
    return $self->{spf} if @_ == 1;
    return $self->{spf} = $value;
}

sub reason( $self, $value = undef ) {
    return $self->{reason} if @_ == 1;
    if ( 'ARRAY' eq ref $value ) {    # one shot argument
        $self->{reason} = $value;
    }
    else {
        push @{ $self->{reason} }, $value;
    }
    return $self->{reason};
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated - row/policy_evaluated section of a DMARC aggregate record

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
