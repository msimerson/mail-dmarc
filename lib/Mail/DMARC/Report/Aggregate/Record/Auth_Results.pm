package Mail::DMARC::Report::Aggregate::Record::Auth_Results;
# VERSION
use strict;
use warnings;

use Carp;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;

sub new {
    my ( $class, @args ) = @_;
    croak "invalid arguments" if @args % 2;

    my $self = bless { spf => [], dkim => [] }, $class;
    return $self if 0 == scalar @args;

    my %args = @args;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }

    return $self;
}

sub spf {
    my ($self, @args) = @_;
    return $self->{spf} if 0 == scalar @args;

    # one shot
    if (1 == scalar @args && ref $args[0] eq 'ARRAY') {
        #warn "SPF one shot";
        my $iter = 0;
        foreach my $d ( @{ $args[0] }) {
            $self->{spf}->[$iter] = 
                Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new($d);
            $iter++;
        }
        return $self->{spf};
    }

    #warn "SPF iterative";
    push @{ $self->{spf} },
        Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new(@args);

    return $self->{spf};
}

sub dkim {
    my ($self, @args) = @_;
    return $self->{dkim} if 0 == scalar @args;

    if (1 == scalar @args && ref $args[0] eq 'ARRAY') {
        #warn "dkim one shot";
        my $iter = 0;
        foreach my $d ( @{ $args[0] }) {
            $self->{dkim}->[$iter] =
                Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new($d);
            $iter++;
        }
        return $self->{dkim};
    }

    #warn "dkim iterative";
    push @{ $self->{dkim}},
        Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(@args);

    return $self->{dkim};
}

1;

# ABSTRACT: auth_results section of a DMARC aggregate record
__END__
