package Mail::DMARC::Result;
# VERSION
use strict;
use warnings;

use Carp;
require Mail::DMARC::Result::Reason;

sub new {
    my $class = shift;
    return bless {
        dkim => '',
        spf  => '',
        reason => [],
        },
        $class;
}

sub published {
    my ( $self, $policy ) = @_;

    if ( !$policy ) {
        if ( !defined $self->{published} ) {
            croak
                "no policy discovered. Did you validate(), or at least fetch_dmarc_record() first? Or inspected results to detect a 'No Results Found' type error?";
        }
        return $self->{published};
    }

    $policy->{domain}
        or croak
        "tag the policy object with a domain indicating where the DMARC record was found!";
    return $self->{published} = $policy;
}

sub disposition {
    return $_[0]->{disposition} if 1 == scalar @_;
    croak "invalid disposition ($_[1]"
        if 0 == grep {/^$_[1]$/ix} qw/ reject quarantine none /;
    return $_[0]->{disposition} = $_[1];
}

sub dkim {
    return $_[0]->{dkim} if 1 == scalar @_;
    croak "invalid dkim" if 0 == grep {/^$_[1]$/ix} qw/ pass fail /;
    return $_[0]->{dkim} = $_[1];
}

sub dkim_align {
    return $_[0]->{dkim_align} if 1 == scalar @_;
    croak "invalid dkim_align"
        if 0 == grep {/^$_[1]$/ix} qw/ relaxed strict /;
    return $_[0]->{dkim_align} = $_[1];
}

sub dkim_meta {
    return $_[0]->{dkim_meta} if 1 == scalar @_;
    return $_[0]->{dkim_meta} = $_[1];
}

sub spf {
    return $_[0]->{spf} if 1 == scalar @_;
    croak "invalid spf" if 0 == grep {/^$_[1]$/ix} qw/ pass fail /;
    return $_[0]->{spf} = $_[1];
}

sub spf_align {
    return $_[0]->{spf_align} if 1 == scalar @_;
    croak "invalid spf_align" if 0 == grep {/^$_[1]$/ix} qw/ relaxed strict /;
    return $_[0]->{spf_align} = $_[1];
}

sub result {
    return $_[0]->{result} if 1 == scalar @_;
    croak "invalid result" if 0 == grep {/^$_[1]$/ix} qw/ pass fail /;
    return $_[0]->{result} = $_[1];
}

sub reason {
    my ($self, @args) = @_;
    return $self->{reason} if ! scalar @args;
    push @{ $self->{reason}}, Mail::DMARC::Result::Reason->new(@args);
    return $self->{reason};
}

1;

# ABSTRACT: an aggregate report result object

