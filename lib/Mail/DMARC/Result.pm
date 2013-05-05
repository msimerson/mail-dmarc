package Mail::DMARC::Result;
# ABSTRACT: DMARC processing results
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC';
use Mail::DMARC::Result::Evaluated;

sub published {
    my ($self, $policy) = @_;

    if ( ! $policy ) {
        if ( ! defined $self->{published} ) {
            croak "no policy discovered. Did you validate(), or at least fetch_dmarc_record() first? Or inspected evaluated results to detect a 'No Results Found' type error?";
        };
        return $self->{published};
    };

    $policy->{domain} or croak "tag the policy object with a domain indicating where the DMARC record was found!";
    return $self->{published} = $policy;
};

sub evaluated {
    my $self = shift;
    return $self->{evaluated} if ref $self->{evaluated};
    return $self->{evaluated} = Mail::DMARC::Result::Evaluated->new();
};

1;
