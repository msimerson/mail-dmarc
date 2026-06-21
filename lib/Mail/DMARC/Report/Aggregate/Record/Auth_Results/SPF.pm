package Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;
use parent 'Mail::DMARC::Base';

sub new( $class, @args ) {

    my $self = bless {}, $class;

    if ( !@args ) {
        return $self;
    }

    # a bare hash
    return $self->_from_hash(@args) if @args > 1;

    my $spf = shift @args;
    return $spf if ref $spf eq $class;

    return $self->_from_hashref($spf) if 'HASH' eq ref $spf;

    croak "invalid spf argument";
}

sub domain( $self, $value = undef ) {
    return $self->{domain} if @_ == 1;
    return $self->{domain} = lc $value;
}

sub result( $self, $value = undef ) {
    return $self->{result} if @_ == 1;
    croak                  if !$self->is_valid_spf_result($value);
    return $self->{result} = $value;
}

sub scope( $self, $value = undef ) {
    return $self->{scope} if @_ == 1;
    croak                 if !$self->is_valid_spf_scope($value);
    return $self->{scope} = $value;
}

sub _from_hash( $self, %args ) {

    foreach my $key ( keys %args ) {

        # scope is frequently absent on received reports
        next if ( $key eq 'scope' && !$args{$key} );
        $self->$key( $args{$key} );
    }

    $self->is_valid;
    return $self;
}

sub _from_hashref( $self, $spf ) {
    return $self->_from_hash( %{$spf} );
}

sub is_valid($self) {

    foreach my $f (qw/ domain result scope /) {
        next if $self->{$f};
        if ( $f ne 'scope' ) {

            # quite a few DMARC reporters don't include scope
            warn "SPF $f is required but missing!\n";
        }
        return 0;
    }

    if ( $self->{result} =~ /^pass$/i && !$self->{domain} ) {
        warn "SPF pass MUST include the RFC5321.MailFrom domain!\n";
        return 0;
    }

    return 1;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF - auth_results/spf section of a DMARC aggregate record

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
