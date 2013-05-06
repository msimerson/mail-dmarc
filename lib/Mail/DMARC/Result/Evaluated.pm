package Mail::DMARC::Result::Evaluated;
# ABSTRACT: the results of applying a DMARC policy
use strict;
use warnings;

use Carp;

sub new {
    my $class = shift;
    return bless {
        dkim   => '',
        spf    => '',
    },
    $class;
}

sub disposition {
    return $_[0]->{disposition} if 1 == scalar @_;
    croak "invalid disposition ($_[1]"
        if 0 == grep {/^$_[1]$/ix} qw/ reject quarantine none /;
    return $_[0]->{disposition} = $_[1];
};

sub dkim {
    return $_[0]->{dkim} if 1 == scalar @_;
    croak "invalid dkim" if 0 == grep {/^$_[1]$/ix} qw/ pass fail /;
    return $_[0]->{dkim} = $_[1];
};

sub dkim_align {
    return $_[0]->{dkim_align} if 1 == scalar @_;
    croak "invalid dkim_align" if 0 == grep {/^$_[1]$/ix} qw/ relaxed strict /;
    return $_[0]->{dkim_align} = $_[1];
};

sub dkim_meta {
    return $_[0]->{dkim_meta} if 1 == scalar @_;
    return $_[0]->{dkim_meta} = $_[1];
};

sub spf {
    return $_[0]->{spf} if 1 == scalar @_;
    croak "invalid spf" if 0 == grep {/^$_[1]$/ix} qw/ pass fail /;
    return $_[0]->{spf} = $_[1];
};

sub spf_align {
    return $_[0]->{spf_align} if 1 == scalar @_;
    croak "invalid spf_align" if 0 == grep {/^$_[1]$/ix} qw/ relaxed strict /;
    return $_[0]->{spf_align} = $_[1];
};

sub reason {
    return $_[0]->{reason} if 1 == scalar @_;
    croak "invalid reason" if 0 == grep {$_[1]->{type} eq $_} 
        qw/ forwarded sampled_out trusted_forwarder
            mailing_list local_policy other /;
    # comment is optional and requires no validation
    return $_[0]->{reason} = $_[1];
};

sub result {
    return $_[0]->{result} if 1 == scalar @_;
    croak "invalid result" if 0 == grep {/^$_[1]$/ix} qw/ pass fail /;
    return $_[0]->{result} = $_[1];
};


1;

__END__
sub {}

=head1 OVERVIEW

An evaluated DMARC result looks like the following data structure:

    disposition  => 'none',   # reject, quarantine, none
    dkim         => 'pass',   # pass, fail
    spf          => 'pass',   # pass, fail
    result       => 'pass',   # pass, fail
    reason       => {
        type     => '',       # forwarded, sampled_out, trusted_forwarder,
        comment  => '',       #   mailing_list, local_policy, other
    },
    dkim_align   => 'strict', # strict, relaxed
    spf_align    => 'strict', # strict, relaxed

The reason and comment fields are optional and may not be present.

The _align fields will only be present if the corresponding field is pass.

=head1 METHODS

=head2 disposition

When the DMARC result is not I<pass>, disposition is the results of applying DMARC policy to a message. Generally this is the same as the header_from domains published DMARC policy. When it is not, the reason SHOULD be specified.

=head2 dkim

Whether the message passed or failed DKIM alignment. In order to pass the DMARC DKIM alignment test, a DKIM signature that matches the RFC5322.From domain must be present. An unsigned messsage, a message with an invalid signature, or signatures that don't match the RFC5322.From field are all considered failures.

=head2 dkim_align

If the message passed the DKIM alignment test, this indicates whether the alignment was strict or relaxed.

=head2 spf

Whether the message passed or failed SPF alignment.

=head2 spf_align

If the message passed the SPF alignment test, this indicates whether the alignment was strict or relaxed.

=head2 reason

If the applied policy differs from the sites published policy, the evaluated policy should contain a reason and optionally a comment. 

    reason => {   
        type =>  '',   
        comment => '',
    },

The following reason types are defined: 

    forwarded
    sampled_out
    trusted_forwarder
    mailing_list
    local_policy
    other

=head2 result

Whether the message passed the DMARC test. In order to pass, at least one of the defined authentication alignments must pass. At present (in 2013) the defined alignments are DKIM and SPF. Possible values are: pass, fail.

=cut
