package Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated;
our $VERSION = '1.20250805';
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

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated - row/policy_evaluated section of a DMARC aggregate record

=head1 VERSION

version 1.20250805

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

This software is copyright (c) 2025 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
