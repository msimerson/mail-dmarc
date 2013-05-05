package Mail::DMARC::Result;
# ABSTRACT: DMARC processing results
use strict;
use warnings;

use Carp;

sub new {
    my $class = shift;
    return bless {}, $class;
};

sub published {
    my ($self, $policy) = @_;
    $policy->{domain} or croak "tag the policy object with a domain indicating where the DMARC record was found!";
    return $self->{published} = $policy;
};

sub evaluated {
#  the results of applying DMARC
    my ($self, $field, $value) = @_;
    return $self->{evaluated}{$field} = $value if $value;
    return $self->{evaluated}{$field} if $field;
    return $self->{evaluated};

#    disposition => '', # reject, quarantine, none
#    dkim        => '', # pass, fail
#    spf         => '', # pass, fail
#    reason      => {   # forwarded, sampled_out, trusted_forwarder,
#        type =>  '',   #   mailing_list, local_policy, other
#        comment => '',
#    },
};

1;
