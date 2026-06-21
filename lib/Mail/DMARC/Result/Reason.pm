package Mail::DMARC::Result::Reason;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;

sub new( $class, @args ) {
    croak "invalid arguments" if @args % 2;
    my %args = @args;
    my $self = bless {}, $class;
    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }
    return $self;
}

sub type( $self, $val = undef ) {
    return $self->{type} if @_ == 1;
    croak "invalid type"
        if !defined $val
        || 0 == grep {/^$val$/ix}
        qw/ forwarded sampled_out trusted_forwarder
        mailing_list local_policy other /;
    return $self->{type} = $val;
}

sub comment( $self, $val = undef ) {
    return $self->{comment} if @_ == 1;

    # comment is optional and requires no validation
    return $self->{comment} = $val;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Result::Reason - policy override reason

=head1 VERSION

version 2.20260621

=head1 METHODS

=head2 type

Type is the type of override used, and is one of a number of fixed strings.

=head2 comment

Comment may or may not be present, and may be anything.

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
