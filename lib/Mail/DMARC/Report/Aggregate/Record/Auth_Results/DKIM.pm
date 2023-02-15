package Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;
our $VERSION = '1.20230215';
use strict;

use Carp;

sub new {
    my ( $class, @args ) = @_;

    croak "missing arguments" if 0 == scalar @args;

    my $self = bless {}, $class;

    # a bare hash
    return $self->_from_hash(@args) if scalar @args > 1;

    my $dkim = shift @args;
    croak "dkim argument not a ref" if ! ref $dkim;

    return $dkim if ref $dkim eq $class;  # been here before...

    return $self->_from_hashref($dkim) if 'HASH' eq ref $dkim;

    croak "invalid dkim argument";
}

sub domain {
    return $_[0]->{domain} if 1 == scalar @_;
    return $_[0]->{domain} =  $_[1];
}

sub selector {
    return $_[0]->{selector} if 1 == scalar @_;
    return $_[0]->{selector} =  $_[1];
}

sub result {
    return $_[0]->{result} if 1 == scalar @_;
    croak "invalid DKIM result" if ! grep { $_ eq $_[1] }
        qw/ pass fail neutral none permerror policy temperror /;
    return $_[0]->{result} =  $_[1];
}

sub human_result {
    return $_[0]->{human_result} if 1 == scalar @_;
    return $_[0]->{human_result} =  $_[1];
}

sub _from_hash {
    my ($self, %args) = @_;

    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }

    $self->is_valid;
    return $self;
}

sub _from_hashref {
    return $_[0]->_from_hash(%{ $_[1] });
}

sub is_valid {
    my $self = shift;

    foreach my $f (qw/ domain result /) {
        if ( ! defined $self->{$f} ) {
            croak "DKIM value $f is required!";
        }
    }
    return;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM - auth_results/dkim section of a DMARC aggregate record

=head1 VERSION

version 1.20230215

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

This software is copyright (c) 2023 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

