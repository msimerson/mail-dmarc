package Mail::DMARC::Report::Aggregate::Record::Auth_Results;
our $VERSION = '1.20240314';
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

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Auth_Results - auth_results section of a DMARC aggregate record

=head1 VERSION

version 1.20240314

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

