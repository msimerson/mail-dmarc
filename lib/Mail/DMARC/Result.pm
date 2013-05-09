package Mail::DMARC::Result;
use strict;
use warnings;

use Carp;

use Mail::DMARC::Result::Evaluated;

sub new {
    my $class = shift;
    return bless { }, $class;
}

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
# ABSTRACT: DMARC processing results
__END__

=head1 METHDS

=head2 published

Published is a L<Mail::DMARC::Policy> object with one extra attribute: domain. The domain attribute is the DNS domain name where the DMARC record was found.

=head2 evaluated

The B<evaluated> method is L<Mail::DMARC::Result::Evaluated> object, containing all of the results from evaluating DMARC policy. See the L<evaluated man page|Mail::DMARC::Result::Evaluated> for details.

=cut
