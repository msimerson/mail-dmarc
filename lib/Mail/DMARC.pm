package Mail::DMARC;
# ABSTRACT: Perl implementation of DMARC
use strict;
use warnings;

use Carp;

=head1 SYNOPSIS

DMARC: a reliable means to authenticate who mail is from.

=cut

sub result {
    my $self = shift;
    croak "invalid use of result\n" if @_;
# result definition
# {
#    dmarc_rr             : the actual DMARC record, as retrieved from DNS
#    dkim_aligned         : strict, relaxed
#    dkim_aligned_domains : hashref of dkim aligned domains and alignment type
#    domain_exists        : boolean
#    error                : description of last error
#    from_domain          :
#    receiving_domain     :
#    message              :
#    spf_aligned          : strict, relaxed
#    policy_requested     :
#    policy_applied       : reject, quarantine, none
#
# }
    return $self->{result};
};

sub result_desc {
    my $self = shift;
    croak "invalid use of result\n" if @_;
    return $self->{result}{error};
};

1;
