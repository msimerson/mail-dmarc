package Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated;
# VERSION
use strict;
use warnings;

use Carp;

sub new {
    my ( $class, @args ) = @_;
    croak "invalid arguments" if @args % 2;
    my %args = @args;
    my $self = bless { reason => [] }, $class;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }
    return $self;
}

sub disposition {
    return $_[0]->{disposition} if 1 == scalar @_;
    croak "invalid disposition ($_[1]"
        if 0 == grep {/^$_[1]$/ix} qw/ reject quarantine none /;
    return $_[0]->{disposition} =  $_[1];
}

sub dkim {
    return $_[0]->{dkim} if 1 == scalar @_;
    return $_[0]->{dkim} =  $_[1];
}

sub spf {
    return $_[0]->{spf} if 1 == scalar @_;
    return $_[0]->{spf} =  $_[1];
}

sub reason {
    return $_[0]->{reason} if 1 == scalar @_;
    if ('ARRAY' eq ref $_[1]) {    # one shot argument
        $_[0]->{reason} = $_[1];
    }
    else {
        push @{ $_[0]->{reason} }, $_[1];
    }
    return $_[0]->{reason};
}

1;

# ABSTRACT: row/policy_evaluated section of a DMARC aggregate record
__END__