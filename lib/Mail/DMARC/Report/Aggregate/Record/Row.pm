package Mail::DMARC::Report::Aggregate::Record::Row;
our $VERSION = '1.20250203';
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

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Row - row section of a DMARC aggregate record

=head1 VERSION

version 1.20250203

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

This software is copyright (c) 2024 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

