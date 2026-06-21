package Mail::DMARC::Report::Aggregate::Record::Row;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;
require Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated;

sub new( $class, @args ) {
    croak "invalid arguments" if @args % 2;
    my %args = @args;
    my $self = bless {}, $class;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }
    return $self;
}

sub source_ip( $self, $value = undef ) {
    return $self->{source_ip} if @_ == 1;
    return $self->{source_ip} = $value;
}

sub policy_evaluated( $self, @args ) {

    if ( !@args ) {
        return $self->{policy_evaluated} if $self->{policy_evaluated};
    }

    if ( @args == 1 ) {
        if ( 'HASH' eq ref $args[0] ) {
            @args = %{ $args[0] };
        }
    }

    return $self->{policy_evaluated}
        = Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated->new(@args);
}

sub count( $self, $value = undef ) {
    return $self->{count} if @_ == 1;
    return $self->{count} = $value;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Row - row section of a DMARC aggregate record

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
