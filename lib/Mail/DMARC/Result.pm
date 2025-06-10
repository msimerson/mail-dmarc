package Mail::DMARC::Result;
our $VERSION = '1.20250610';
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
    croak "invalid result" if 0 == grep {/^$_[1]$/ix} qw/ pass fail none /;
    return $_[0]->{result} = $_[1];
}

sub reason {
    my ($self, @args) = @_;
    return $self->{reason} if ! scalar @args;
    push @{ $self->{reason}}, Mail::DMARC::Result::Reason->new(@args);
    return $self->{reason};
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Result - an aggregate report result object

=head1 VERSION

version 1.20250610

=head1 OVERVIEW

A L<Result|Mail::DMARC::Result> object is the product of instantiating a L<DMARC::PurePerl|Mail::DMARC::PurePerl> object, populating the variables, and running $dmarc->validate. The results object looks like this:

    result       => 'pass',   # pass, fail
    disposition  => 'none',   # reject, quarantine, none
    reason       => [         # there can be many reasons...
            {
                type     => '',   # forwarded, sampled_out, trusted_forwarder,
                comment  => '',   #   mailing_list, local_policy, other
            },
        ],
    dkim         => 'pass',   # pass, fail
    dkim_align   => 'strict', # strict, relaxed
    spf          => 'pass',   # pass, fail
    spf_align    => 'strict', # strict, relaxed
    published    => L<Mail::DMARC::Policy>,

Reasons are optional and may not be present.

The dkim_align and spf_align fields will only be present if the corresponding test value equals pass. They are additional info not specified by the DMARC spec.

=head1 METHODS

=head2 published

Published is a L<Mail::DMARC::Policy> tagged with a domain. The domain attribute is the DNS domain name where the DMARC record was found. This may not be the same as the header_from domain (ex: bounces.amazon.com -vs- amazon.com).

=head2 result

Whether the message passed the DMARC test. Possible values are: pass, fail.

In order to pass, at least one authentication alignment must pass. The 2013 draft defines two authentication methods: DKIM and SPF. The list is expected to grow.

=head2 disposition

When the DMARC result is not I<pass>, disposition is the results of applying DMARC policy to a message. Generally this is the same as the header_from domains published DMARC L<policy|Mail::DMARC::Policy>. When it is not, the reason SHOULD be specified.

=head2 dkim

Whether the message passed or failed DKIM alignment. In order to pass the DMARC DKIM alignment test, a DKIM signature that matches the RFC5322.From domain must be present. An unsigned messsage, a message with an invalid signature, or signatures that don't match the RFC5322.From field are all considered failures.

=head2 dkim_align

If the message passed the DKIM alignment test, this indicates whether the alignment was strict or relaxed.

=head2 spf

Whether the message passed or failed SPF alignment. To pass SPF alignment, the RFC5321.MailFrom domain must match the RFC5322.From field.

=head2 spf_align

If the message passed the SPF alignment test, this indicates whether the alignment was strict or relaxed.

=head2 reason

If the applied policy differs from the sites published policy, the result policy should contain a reason and optionally a comment.

A DMARC result reason has two attributes, type, and comment.

    reason => {
        type =>  '',
        comment => '',
    },

=head3 type

The following reason types are defined and valid:

    forwarded
    sampled_out
    trusted_forwarder
    mailing_list
    local_policy
    other

=head3 comment

Comment is a free form text field.

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

This software is copyright (c) 2025 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

