package Mail::DMARC::Result::Reason;
# VERSION
use strict;
use warnings;

use Carp;

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

sub type {
    return $_[0]->{type} if 1 == scalar @_;
    croak "invalid type"
        if 0 == grep {/^$_[1]$/ix}
        qw/ forwarded sampled_out trusted_forwarder
            mailing_list local_policy other /;
    return $_[0]->{type} = $_[1];
}

sub comment {
    return $_[0]->{comment} if 1 == scalar @_;

    # comment is optional and requires no validation
    return $_[0]->{comment} = $_[1];
}

1;

# ABSTRACT: policy override reason
__END__

=head1 METHODS

=head2 type

Type is the type of override used, and is one of a number of fixed strings.

=head2 comment

Comment may or may not be present, and may be anything.

