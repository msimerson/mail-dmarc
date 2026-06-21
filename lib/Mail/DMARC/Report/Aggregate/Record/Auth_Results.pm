package Mail::DMARC::Report::Aggregate::Record::Auth_Results;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;

sub new( $class, @args ) {
    croak "invalid arguments" if @args % 2;

    my $self = bless { spf => [], dkim => [] }, $class;
    return $self if !@args;

    my %args = @args;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }

    return $self;
}

sub spf( $self, @args ) {
    return $self->{spf} if !@args;

    # one shot
    if ( @args == 1 && ref $args[0] eq 'ARRAY' ) {

        #warn "SPF one shot";
        my $iter = 0;
        foreach my $d ( @{ $args[0] } ) {
            $self->{spf}->[$iter]
                = Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new(
                $d);
            $iter++;
        }
        return $self->{spf};
    }

    #warn "SPF iterative";
    push @{ $self->{spf} },
        Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new(@args);

    return $self->{spf};
}

sub dkim( $self, @args ) {
    return $self->{dkim} if !@args;

    if ( @args == 1 && ref $args[0] eq 'ARRAY' ) {

        #warn "dkim one shot";
        my $iter = 0;
        foreach my $d ( @{ $args[0] } ) {
            $self->{dkim}->[$iter]
                = Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(
                $d);
            $iter++;
        }
        return $self->{dkim};
    }

    #warn "dkim iterative";
    push @{ $self->{dkim} },
        Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(@args);

    return $self->{dkim};
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Auth_Results - auth_results section of a DMARC aggregate record

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
