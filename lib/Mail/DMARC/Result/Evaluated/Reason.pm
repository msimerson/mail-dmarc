package Mail::DMARC::Result::Evaluated::Reason;
use strict;
use warnings;

use Carp;

sub new {
    my $class = shift;
    return bless { @_ }, $class;
}

sub type {
    return $_[0]->{type} if 1 == scalar @_;
    croak "invalid type" if 0 == grep {/^$_[1]$/ix}
        qw/ forwarded sampled_out trusted_forwarder
            mailing_list local_policy other /;
    return $_[0]->{type} = $_[1];
};

sub comment {
    return $_[0]->{comment} if 1 == scalar @_;
    # comment is optional and requires no validation
    return $_[0]->{comment} = $_[1];
};

1;
# ABSTRACT: a DMARC evaluated policy reason
__END__
sub {}

=head1 OVERVIEW

An evaluated DMARC result reason has two attributes, type, and comment.


=head1 METHODS

=head2 type

The following reason types are defined and valid:

    forwarded
    sampled_out
    trusted_forwarder
    mailing_list
    local_policy
    other

=head2 comment

Comment is a free form text field.

=cut
