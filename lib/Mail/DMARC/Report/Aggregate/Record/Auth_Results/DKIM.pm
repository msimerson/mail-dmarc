package Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;

sub new( $class, @args ) {

    croak "missing arguments" if !@args;

    my $self = bless {}, $class;

    # a bare hash
    return $self->_from_hash(@args) if @args > 1;

    my $dkim = shift @args;
    croak "dkim argument not a ref" if !ref $dkim;

    return $dkim if ref $dkim eq $class;    # been here before...

    return $self->_from_hashref($dkim) if 'HASH' eq ref $dkim;

    croak "invalid dkim argument";
}

sub domain( $self, $value = undef ) {
    return $self->{domain} if @_ == 1;
    return $self->{domain} = $value;
}

sub selector( $self, $value = undef ) {
    return $self->{selector} if @_ == 1;
    return $self->{selector} = $value;
}

sub result( $self, $value = undef ) {
    return $self->{result} if @_ == 1;
    croak "invalid DKIM result"
        if !grep { $_ eq $value }
        qw/ pass fail neutral none permerror policy temperror /;
    return $self->{result} = $value;
}

sub human_result( $self, $value = undef ) {
    return $self->{human_result} if @_ == 1;
    return $self->{human_result} = $value;
}

sub _from_hash( $self, %args ) {

    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }

    $self->is_valid;
    return $self;
}

sub _from_hashref( $self, $dkim ) {
    return $self->_from_hash( %{$dkim} );
}

sub is_valid($self) {

    foreach my $f (qw/ domain result /) {
        if ( !defined $self->{$f} ) {
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
