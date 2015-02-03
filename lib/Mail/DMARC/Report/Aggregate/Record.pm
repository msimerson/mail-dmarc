package Mail::DMARC::Report::Aggregate::Record;
# VERSION
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

    if (! scalar @args) {
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

# ABSTRACT: record section of aggregate report
__END__

=head1 DESCRIPTION

An aggregate report record, with object methods for identifiers, auth_results, and each row.

=cut
