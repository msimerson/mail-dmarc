package Mail::DMARC::Report::Aggregate::Record::Row;
# VERSION
use strict;
use warnings;

use Carp;
require Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated;

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

sub source_ip {
    return $_[0]->{source_ip} if 1 == scalar @_;
    return $_[0]->{source_ip} =  $_[1];
}

sub policy_evaluated {
    my ($self, @args) = @_;

    if (0 == scalar @args) {
        return $self->{policy_evaluated} if $self->{policy_evaluated};
    }

    if (1 == scalar @args) {
        if ('HASH' eq ref $args[0]) {
            @args = %{ $args[0] };
        }        
    }

    return $self->{policy_evaluated} =
        Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated->new(@args);
}

sub count {
    return $_[0]->{count} if 1 == scalar @_;
    return $_[0]->{count} =  $_[1];
}

1;

# ABSTRACT: row section of a DMARC aggregate record
__END__