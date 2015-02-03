package Mail::DMARC::Report::Aggregate::Record::Identifiers;
# VERSION
use strict;
use warnings;

use Carp;

sub new {
    my ( $class, @args ) = @_;
    croak "invalid arguments" if @args % 2;
    my %args = @args;
    my $self = bless {}, $class;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }
    return $self;
}

sub envelope_to {
    return $_[0]->{envelope_to} if 1 == scalar @_;
    return $_[0]->{envelope_to} = $_[1];
}

sub envelope_from {
    return $_[0]->{envelope_from} if 1 == scalar @_;
    return $_[0]->{envelope_from} = $_[1];
}

sub header_from {
    return $_[0]->{header_from} if 1 == scalar @_;
    return $_[0]->{header_from} = $_[1];
}

1;

# ABSTRACT: identifiers section of a DMARC aggregate record
__END__