package Mail::DMARC::PurePerl;
# ABSTRACT: a perl implementation of DMARC

use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC';

sub dns {
    my $self = shift;
    $self->{dns} ||= Mail::DMARC::DNS->new();
    return $self->{dns};
};

sub init {
    my $self = shift;
    $self->{is_subdomain} = undef;
    $self->{policy} = undef;
    $self->{result} = undef;
    return;
};

sub validate {
    my $self = shift;

    # 11.1.  Extract Author Domain
    my $from_dom = $self->get_from_dom() or return;

    # 6. Receivers should reject email if the domain appears to not exist
    $self->exists_in_dns() or return;

    # 11.2.  Determine Handling Policy
    my $policy = $self->discover_policy() or return;

    #   3.  Perform DKIM signature verification checks.  A single email may
    #       contain multiple DKIM signatures.  The results MUST include the
    #       value of the "d=" tag from all DKIM signatures that validated.
    #   4.  Perform SPF validation checks.  The results of this step
    #       MUST include the domain name from the RFC5321.MailFrom if SPF
    #       evaluation returned a "pass" result.
    #   5.  Conduct identifier alignment checks.
    $self->is_aligned() and return 1;

    my $effective_p = $self->is_subdomain && defined $policy->sp
            ? $policy->sp
            : $policy->p;

    #   6.  Apply policy.  Emails that fail the DMARC mechanism check are
    #       disposed of in accordance with the discovered DMARC policy of the
    #       Domain Owner.  See Section 6.2 for details.
    if ( lc $effective_p eq 'none' ) {
        $self->result->evaluated->result('pass');
        return;
    };

# 7.1.  Policy Fallback Mechanism
# If the "pct" tag is present in a policy record, application of policy
# is done on a selective basis.
    if ( ! defined $policy->pct ) {
        $self->result->evaluated->disposition($effective_p);
        return;
    };

# The stated percentage of messages that fail the DMARC test MUST be
# subjected to whatever policy is selected by the "p" or "sp" tag
    if ( int(rand(100)) >= $policy->pct ) {
        $self->result->evaluated->disposition('none');
        $self->result->evaluated->reason( {type=>'sampled_out'} );
        return;
    };

# Those that are not thus
# selected MUST instead be subjected to the next policy lower in terms
# of severity.  In decreasing order of severity, the policies are
# "reject", "quarantine", and "none".
#
# For example, in the presence of "pct=50" in the DMARC policy record
# for "example.com", half of the mesages with "example.com" in the
# RFC5322.From field which fail the DMARC test would be subjected to
# "reject" action, and the remainder subjected to "quarantine" action.

    $self->result->evaluated->disposition(
        ( $effective_p eq 'reject' ) ? 'quarantine' : 'none' );
    return;
}

sub discover_policy {
    my $self = shift;
    my $from_dom = shift || $self->header_from or croak;
    my $org_dom  = $self->get_organizational_domain($from_dom);

    my $e = $self->result->evaluated;

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record...
    my $matches = $self->fetch_dmarc_record($from_dom, $org_dom) or do {
        $e->disposition('none');
        $e->reason( { type=>'other', comment => 'no DMARC records' } );
        return;
    };

    # 4.  Records that do not include a "v=" tag that identifies the
    #     current version of DMARC are discarded.
    my @matches = grep {/^v=DMARC1/ix} @$matches;
    if (0 == scalar @matches) {
        $e->disposition('none');
        $e->reason( { type=>'other', comment=> "no valid DMARC record" });
        return;
    }

    # 5.  If the remaining set contains multiple records, processing
    #     terminates and the Mail Receiver takes no action.
    if (@matches > 1) {
        $e->disposition('none');
        $e->reason( {type=>'other', comment=> "too many DMARC records" });
        return;
    }

#   $e->dmarc_rr($matches[0]);  # why save this?

    # 6.  If a retrieved policy record does not contain a valid "p" tag, or
    #     contains an "sp" tag that is not valid, then:
    my $policy = $self->policy( $matches[0] ) or return;
    $policy->{domain} = $from_dom;
    $self->result->published( $policy );
    if (!$policy->p || !$policy->is_valid_p($policy->p)
            || (defined $policy->sp && ! $policy->is_valid_p($policy->sp) ) ) {

        #   A.  if an "rua" tag is present and contains at least one
        #       syntactically valid reporting URI, the Mail Receiver SHOULD
        #       act as if a record containing a valid "v" tag and "p=none"
        #       was retrieved, and continue processing;
        #   B.  otherwise, the Mail Receiver SHOULD take no action.
        if (!$policy->rua || !$self->has_valid_reporting_uri($policy->rua)) {
            $e->disposition('none');
            $e->reason( { type=>'other', comment=> "no valid reporting rua" });
            return;
        }
        $policy->v( 'DMARC1' );
        $policy->p( 'none' );
    }

    return $policy;
}

sub is_aligned {
    my $self = shift;

    #   5.  Conduct identifier alignment checks.  With authentication checks
    #       and policy discovery performed, the Mail Receiver checks if
    #       Authenticated Identifiers fall into alignment as decribed in
    #       Section 4.  If one or more of the Authenticated Identifiers align
    #       with the RFC5322.From domain, the message is considered to pass
    #       the DMARC mechanism check.  All other conditions (authentication
    #       failures, identifier mismatches) are considered to be DMARC
    #       mechanism check failures.

    #   DMARC has no "short-circuit" provision, such as specifying that a
    #   pass from one authentication test allows one to skip the other(s).
    #   All are required for reporting.

    $self->is_dkim_aligned;
    $self->is_spf_aligned;

    if (    'pass' eq $self->result->evaluated->spf
         || 'pass' eq $self->result->evaluated->dkim ) {
        $self->result->evaluated->result('pass');
        return 1;
    };
    return 0;
};

sub is_dkim_aligned {
    my $self = shift;

    my $from_dom  = $self->header_from or croak "header_from not set!";
    my $dkim_sigs = $self->dkim or croak "missing dkim!";
    if ( 'ARRAY' ne ref $dkim_sigs ) {
        croak "dkim needs to be an array reference!";
    };

    my (@dkim_pass_doms) = grep {
               $_->{result} eq 'pass'
            && $_->{domain} eq $from_dom
    } @$dkim_sigs;

    my $policy   = $self->policy or croak "no policy!?";
    my $from_org = $self->get_organizational_domain();

# Required in report: DKIM-Domain, DKIM-Identity, DKIM-Selector
    foreach my $dkim_ref (@dkim_pass_doms) {
        my $dkim_dom = $dkim_ref->{domain};

        # 4.3.1 make sure $dkim_dom is not a public suffix
        next if $self->dns->is_public_suffix($dkim_dom);

        if ($dkim_dom eq $from_dom) { # strict alignment requires exact match
            $self->result->evaluated->dkim('pass');
            $self->result->evaluated->dkim_meta( {
                    domain   => $dkim_dom,
                    identity => '',  # TODO
                    selector => $dkim_ref->{selector},
                    } );
            last;
        }

        # don't try relaxed if policy specifies strict
        next if $policy->adkim && lc $policy->adkim eq 's';

        # don't try relaxed if we already got a strict match
        next if 'pass' eq $self->result->evaluated->dkim;

        # relaxed policy (default): Org. Dom must match a DKIM sig
        my $dkim_org = $self->get_organizational_domain($dkim_dom);
        if ( $dkim_org eq $from_org ) {
            $self->result->evaluated->dkim('pass');
            $self->result->evaluated->dkim_meta( {
                    domain   => $dkim_org,
                    identity => '',   # TODO
                    selector => $dkim_ref->{selector},
                    } );
        };
    };
    return 1 if 'pass' eq $self->result->evaluated->dkim;
    return;
};

sub is_spf_aligned {
    my $self = shift;
    my $spf_dom = shift;
    if ( ! $spf_dom && ! $self->spf ) { croak "missing SPF!"; };
    $spf_dom = $self->spf->{domain} if ! $spf_dom;
    $spf_dom or croak "missing SPF domain";

    if ( ! $spf_dom ) {
        $self->result->evaluated->spf('fail');
        return 0;
    };

    my $from_dom = $self->header_from or croak "header_from not set!";

    if ($spf_dom eq $from_dom) {
        $self->result->evaluated->spf('pass');
        $self->result->evaluated->spf_align('strict');
        return 1;
    }

    # don't try relaxed match if strict policy requested
    return 0 if ($self->policy->aspf && lc $self->policy->aspf eq 's' );

    if (     $self->get_organizational_domain( $spf_dom )
          eq $self->get_organizational_domain( $from_dom ) ) {
        $self->result->evaluated->spf('pass');
        $self->result->evaluated->spf_align('relaxed');
        return 1;
    }
    return 0;
};

sub is_subdomain {
    return $_[0]->{is_subdomain} if 1 == scalar @_;
    croak "invalid boolean" if 0 == grep {/^$_[1]$/ix} qw/ 0 1/;
    return $_[0]->{is_subdomain} = $_[1];
};

sub has_valid_reporting_uri {
    my ($self, $rua) = @_;
    return 1 if 'mailto:' eq lc substr($rua, 0, 7);
    return 0;
}

sub get_organizational_domain {
    my $self = shift;
    my $from_dom = shift || $self->header_from or croak "missing header_from!";

    # 1.  Acquire a "public suffix" list, i.e., a list of DNS domain
    #     names reserved for registrations. http://publicsuffix.org/list/

    # 2.  Break the subject DNS domain name into a set of "n" ordered
    #     labels.  Number these labels from right-to-left; e.g. for
    #     "example.com", "com" would be label 1 and "example" would be
    #     label 2.;
    my @labels = reverse split /\./, $from_dom;

    # 3.  Search the public suffix list for the name that matches the
    #     largest number of labels found in the subject DNS domain.  Let
    #     that number be "x".
    my $greatest = 0;
    for (my $i = 0 ; $i <= scalar @labels ; $i++) {
        next if !$labels[$i];
        my $tld = join '.', reverse((@labels)[0 .. $i]);

        #carp "i: $i -  tld: $tld\n";
        if ( $self->dns->is_public_suffix($tld) ) {
            $greatest = $i + 1;
        }
    }

    if ( $greatest == scalar @labels ) {      # same
        return $from_dom;
    };

    # 4.  Construct a new DNS domain name using the name that matched
    #     from the public suffix list and prefixing to it the "x+1"th
    #     label from the subject domain. This new name is the
    #     Organizational Domain.
    return join '.', reverse((@labels)[0 .. $greatest]);
}

sub exists_in_dns {
    my $self = shift;
    my $from_dom = shift || $self->header_from or croak "no header_from!";
# 6. Receivers should endeavour to reject or quarantine email if the
#    RFC5322.From purports to be from a domain that appears to be
#    either non-existent or incapable of receiving mail.

# That's all the draft says. I went back to the DKIM ADSP (which led me to
# the ietf-dkim email list where some 'experts' failed to agree on The Right
# Way to test domain validity. Let alone deliverability. They point out:
# MX records aren't mandatory, and A or AAAA as fallback aren't reliable.
#
# Some experimentation proved both cases in real world usage. Instead, I test
# existence by searching for a MX, NS, A, or AAAA record. Since this search
# is repeated for the Organizational Name, if the NS query fails, there's no
# delegation from the TLD. That has proven very reliable.
    my $org_dom = $self->get_organizational_domain( $from_dom );
    my @todo = $from_dom;
    if ( $from_dom ne $org_dom ) {
        push @todo, $org_dom;
        $self->is_subdomain(1);
    };
    my $matched = 0;
    foreach ( @todo ) {
        last if $matched;
        $matched++ and next if $self->dns->has_dns_rr('MX', $_);
        $matched++ and next if $self->dns->has_dns_rr('NS', $_);
        $matched++ and next if $self->dns->has_dns_rr('A',  $_);
        $matched++ and next if $self->dns->has_dns_rr('AAAA', $_);
    };
    $self->result->evaluated->disposition('none') if $matched;
    $self->result->evaluated->reason(
            {type=>'other', comment => "$from_dom not in DNS"}) if ! $matched;
    return $matched;
}

sub fetch_dmarc_record {
    my ($self, $zone, $org_dom) = @_;

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
    #     DNS domain matching the one found in the RFC5322.From domain in
    #     the message. A possibly empty set of records is returned.
    $self->is_subdomain( defined $org_dom ? 0 : 1 );
    my @matches = ();
    my $res = $self->dns->get_resolver();
    my $query = $res->send('_dmarc.' . $zone, 'TXT') or return \@matches;
    for my $rr ($query->answer) {
        next if $rr->type ne 'TXT';

        #   2.  Records that do not start with a "v=" tag that identifies the
        #       current version of DMARC are discarded.
        next if 'v=' ne lc substr($rr->txtdata, 0, 2);
        next if 'v=spf' eq lc substr($rr->txtdata, 0, 5); # SPF commonly found
        push @matches, join('', $rr->txtdata);
    }
    return \@matches if scalar @matches;  # found one! (at least)

    #   3.  If the set is now empty, the Mail Receiver MUST query the DNS for
    #       a DMARC TXT record at the DNS domain matching the Organizational
    #       Domain in place of the RFC5322.From domain in the message (if
    #       different).  This record can contain policy to be asserted for
    #       subdomains of the Organizational Domain.
    if ( defined $org_dom ) {                         #   <- recursion break
        return \@matches if $org_dom eq $zone;
        return $self->fetch_dmarc_record($org_dom);   #   <- recursion
    };

#carp "no policy for $zone\n";
    return \@matches;
}

sub get_from_dom {
    my ($self) = @_;

    if ( ! $self->header_from ) {
        return $self->get_dom_from_header();
    };

    return $self->header_from;
};

sub get_dom_from_header {
    my $self = shift;
    my $header = $self->header_from_raw or croak "no header or raw_header!";

# Should I do something special with a From field with multiple addresses?
# Do what if the domains differ? This returns only the last.
# Callers can pass in pre-parsed from_dom if this doesn't suit them.
#
# I only care about extracting the domain. This is way faster than attempting
# to parse a RFC822 address.
    if ( 'from:' eq lc substr($header,0,5) ) { # if From: prefix is present
        $header = substr $header, 6;           # remove it
    };

    my ($from_dom) = (split /@/, $header)[-1]; # grab everything after the @
    ($from_dom) = split /\s+/, $from_dom;      # remove any trailing cruft
    chomp $from_dom;                           # remove \n
    chop $from_dom if '>' eq substr($from_dom, -1, 1); # remove closing >
    return $self->header_from($from_dom);
}

sub external_report {
    my $self = shift;
# TODO:
    return;
};

sub verify_external_reporting {
    my $self = shift;
# TODO
    return;
}

1;
