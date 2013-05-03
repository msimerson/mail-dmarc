package Mail::DMARC;
# ABSTRACT: Perl implementation of DMARC
use strict;
use warnings;

use Carp;

=head1 SYNOPSIS

DMARC: a reliable means to authenticate who mail is from.

=cut

sub inputs {
    my ($self, $dkim, $spf) = @_;
    return
    {
        source_ip       => '',
        envelope_to     => '',   # envelope recipient domain
        envelope_from   => '',   # envelope from domain
        header_from     => '',   # header from domain
        header_from_raw => '',   # in lieu of header_from

        dkim => [
            {
                domain      => $dkim->signature->domain,   # The d= parameter in the signature
                selector    => $dkim->signature->selector, # The s= parameter in the signature
                result      => $dkim->result,  # none,pass,fail,policy,neutral,temperror, permerror
                human_result=> $dkim->result_detail,
            },
        ],
        spf => {
            domain => $spf->identity, # checked domain
            scope  => $spf->scope, # scope of checked domain: mfrom, helo
            result => $spf->code,  # none, neutral, pass, fail, softfail, temperror, permerror
        },
    }
};

sub result {
    {
        PolicyPublished => {
            domain => '',    # The domain where the DMARC record was found.
            adkim  => '',    # The DKIM alignment mode
            aspf   => '',    # SPF alignment mode
            p      => '',    # The policy to apply to messages from the domain
            sp     => '',    # The policy to apply to messages from subdomains
            pct    => '',    # The percent of messages to which policy applies
        },
        PolicyEvaluated => { #  the results of applying DMARC
            disposition => '', # reject, quarantine, none
            dkim        => '', # pass, fail
            spf         => '', # pass, fail
            reason      => {   # forwarded, sampled_out, trusted_forwarder,
                type =>  '',   #   mailing_list, local_policy, other
                comment => '',
            },
        },
    };
};

1;
