package Mail::DMARC::Result;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

use Carp;
require Mail::DMARC::Result::Reason;

sub new($class) {
    return bless {
        dkim   => '',
        spf    => '',
        reason => [],
        },
        $class;
}

sub published( $self, $policy = undef ) {
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

sub disposition( $self, $val = undef ) {
    return $self->{disposition} if @_ == 1;
    croak 'invalid disposition: ' . ( $val // '(undef)' )
        if !defined $val || 0 == grep {/^$val$/ix} qw/ reject quarantine none /;
    return $self->{disposition} = $val;
}

sub dkim( $self, $val = undef ) {
    return $self->{dkim} if @_ == 1;
    croak "invalid dkim" if 0 == grep {/^$val$/ix} qw/ pass fail /;
    return $self->{dkim} = $val;
}

sub dkim_align( $self, $val = undef ) {
    return $self->{dkim_align} if @_ == 1;
    croak "invalid dkim_align"
        if 0 == grep {/^$val$/ix} qw/ relaxed strict /;
    return $self->{dkim_align} = $val;
}

sub dkim_meta( $self, $val = undef ) {
    return $self->{dkim_meta} if @_ == 1;
    return $self->{dkim_meta} = $val;
}

sub spf( $self, $val = undef ) {
    return $self->{spf} if @_ == 1;
    croak "invalid spf" if 0 == grep {/^$val$/ix} qw/ pass fail /;
    return $self->{spf} = $val;
}

sub spf_align( $self, $val = undef ) {
    return $self->{spf_align} if @_ == 1;
    croak "invalid spf_align" if 0 == grep {/^$val$/ix} qw/ relaxed strict /;
    return $self->{spf_align} = $val;
}

sub result( $self, $val = undef ) {
    return $self->{result} if @_ == 1;
    croak "invalid result"
        if !defined $val || 0 == grep {/^$val$/ix} qw/ pass fail none /;
    return $self->{result} = $val;
}

sub reason( $self, @args ) {
    return $self->{reason} if !@args;
    push @{ $self->{reason} }, Mail::DMARC::Result::Reason->new(@args);
    return $self->{reason};
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Result - an aggregate report result object

=head1 VERSION

version 2.20260621

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

This software is copyright (c) 2026 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
