package Mail::DMARC::Report::Aggregate::Record;
# VERSION
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC::Base';

sub identifiers {
    my ($self, @args) = @_;
    return $self->{identifiers} if ! scalar @args;
    croak "missing identifier"  if ! $args[0];
    my %id = 1 == scalar @args ? %{ $args[0] }
           : scalar @args % 2 == 0 ? @args
           : croak "identifiers is required!";

    croak "identifiers/header_from is required!" if ! $id{header_from};
    carp "identifiers/envelope_from is missing!" if ! $id{envelope_from};
    return $self->{identifiers} = \%id;
}

sub auth_results {
    my ($self, @args) = @_;
    return $self->{auth_results} if ! scalar @args;
    my %auth = 1 == scalar @args ? %{ $args[0] }
           : scalar @args % 2 == 0 ? @args
           : croak "auth_results is required!";

    croak "auth_results/spf is required!" if ! $auth{spf};
    carp "auth_results/dkim is missing!" if ! $auth{dkim};

    return $self->{auth_results} = \%auth;
}

sub row {
    my ($self, @args) = @_;
    return $self->{row} if ! scalar @args;
    croak "invalid row value!" if ! $args[0];
    my %row = 1 == scalar @args     ? %{ $args[0] }
            : 0 == scalar @args % 2 ? @args
            : croak "row is required!";

    croak "row/source_ip is required!" if ! $row{source_ip};
    croak "row/count is missing!" if ! $row{count};
    croak "row/policy_evaluated is missing!" if ! $row{policy_evaluated};

    return $self->{row} = \%row;
}

1;
# ABSTRACT: record section of aggregate report
__END__
sub {}



