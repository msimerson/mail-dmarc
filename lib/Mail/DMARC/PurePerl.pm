package Mail::DMARC::PurePerl;
# ABSTRACT: a perl implementation of DMARC

use strict;
use warnings;

use Carp;
use IO::File;
use Net::DNS::Resolver;

use lib 'lib';
use parent 'Mail::DMARC';
use Mail::DMARC::Policy;

sub new {
    my $self = shift;
    return bless {
        dns_timeout   => 5,
        is_subdomain  => undef,
        resolver      => undef,
        ps_file       => 'share/public_suffix_list',
    },
    $self;
}

sub init {
    my $self = shift;
    $self->{policy}       = undef;
    $self->{result}       = {};
    $self->{is_subdomain} = undef;
    return;
};

sub is_valid {
    my ($self, @a) = @_;
    croak "invalid request" if @a % 2 != 0;
    my %args = @a;

    # 11.1.  Extract Author Domain
    my $from_dom = $self->get_from_dom( \%args ) or return;
    my $org_dom  = $self->get_organizational_domain($from_dom);

    # 6. Receivers should reject email if the domain appears to not exist
    $self->exists_in_dns($from_dom, $org_dom) or return;

    # 11.2.  Determine Handling Policy
    my $policy = $self->discover_policy($from_dom, $org_dom) or return;

    #   3.  Perform DKIM signature verification checks.  A single email may
    #       contain multiple DKIM signatures.  The results MUST include the
    #       value of the "d=" tag from all DKIM signatures that validated.
    #   4.  Perform SPF validation checks.  The results of this step
    #       MUST include the domain name from the RFC5321.MailFrom if SPF
    #       evaluation returned a "pass" result.
    #   5.  Conduct identifier alignment checks.
    return 1 if $self->is_aligned(
            dkim_doms      => $args{dkim_pass_domains},
            spf_pass_domain=> $args{spf_pass_dom},
            );

    #   6.  Apply policy.  Emails that fail the DMARC mechanism check are
    #       disposed of in accordance with the discovered DMARC policy of the
    #       Domain Owner.  See Section 6.2 for details.
    if ( $self->{is_subdomain} && defined $policy->sp ) {
        return 1 if lc $policy->sp eq 'none';
    };
    return 1 if lc $policy->p eq 'none';

# If the "pct" tag is present in a policy record, application of policy
# is done on a selective basis.  The stated percentage of messages that
# fail the DMARC test MUST be subjected to whatever policy is selected
# by the "p" or "sp" tag (if present).  Those that are not thus
# selected MUST instead be subjected to the next policy lower in terms
# of severity.  In decreasing order of severity, the policies are
# "reject", "quarantine", and "none".
#
# For example, in the presence of "pct=50" in the DMARC policy record
# for "example.com", half of the mesages with "example.com" in the
# RFC5322.From field which fail the DMARC test would be subjected to
# "reject" action, and the remainder subjected to "quarantine" action.

# TODO: move this into a sub, add results to $self->{report}
    if ( $policy->pct != 100 && int(rand(100)) >= $policy->pct ) {
        carp "fail, tolerated, policy, sampled out";
        return;
    };

    carp "failed DMARC policy\n";
    return;
}

sub discover_policy {
    my ($self, $from_dom, $org_dom) = @_;
    $from_dom ||= $self->{result}{from_domain};
    $org_dom  ||= $self->{result}{org_domain};

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record...
    my $matches = $self->fetch_dmarc_record($from_dom, $org_dom) or do {
        $self->{result}{error} = "no DMARC records";
        return;
    };

    # 4.  Records that do not include a "v=" tag that identifies the
    #     current version of DMARC are discarded.
    my @matches = grep {/^v=DMARC1/i} @$matches; ## no critic (ExtendedFormatting)
    if (0 == scalar @matches) {
        $self->{result}{error} = "no valid DMARC record";
        return;
    }

    # 5.  If the remaining set contains multiple records, processing
    #     terminates and the Mail Receiver takes no action.
    if (@matches > 1) {
        $self->{result}{error} = "too many DMARC records";
        return;
    }

    $self->{result}{dmarc_rr} = $matches[0];

    # 6.  If a retrieved policy record does not contain a valid "p" tag, or
    #     contains an "sp" tag that is not valid, then:
    my $policy = Mail::DMARC::Policy->new( $matches[0] ) or return;
    if (!$policy->is_valid_p($policy->p)
            || (defined $policy->sp && ! $policy->is_valid_p($policy->sp) ) ) {

        #   A.  if an "rua" tag is present and contains at least one
        #       syntactically valid reporting URI, the Mail Receiver SHOULD
        #       act as if a record containing a valid "v" tag and "p=none"
        #       was retrieved, and continue processing;
        #   B.  otherwise, the Mail Receiver SHOULD take no action.
        if (!$policy->rua || !$self->has_valid_reporting_uri($policy->rua)) {
            $self->{result}{error} = "no valid reporting rua";
            return;
        }
        $policy->v( 'DMARC1' );
        $policy->p( 'none' );
    }

    return $policy;
}

sub is_aligned {
    my ($self, @a) = @_;
    croak "invalid arguments to is_aligned\n" if @a % 2 != 0;
    my %args = @a;

    $self->{result}{from_domain} = $args{from_domain} if $args{from_domain};
    $self->{result}{org_domain}  = $args{org_domain}  if $args{org_domain};
    $self->{policy} = $args{policy} if $args{policy};
    $args{from_domain} = $self->{result}{from_domain} || croak "missing from domain";
    my $spf_dom   = $args{spf_pass_domain}   || '';
    my $dkim_doms = $args{dkim_pass_domains} || [];

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

    $self->is_dkim_aligned( $dkim_doms );
    $self->is_spf_aligned( $spf_dom );

    return 1 if $self->{result}{spf_aligned} || $self->{result}{dkim_aligned};
    return 0;
};

sub is_dkim_aligned {
    my $self = shift;
    my $dkim_pass_doms = shift or return;

# TODO: Required in report: DKIM-Domain, DKIM-Identity, DKIM-Selector
    my $from_dom = $self->{result}{from_domain} or croak "from_domain not set!";
    my $policy   = $self->policy or croak "no policy!?";
    my $org_dom  = $self->{result}{org_domain} || $self->get_organizational_domain();

    foreach (@$dkim_pass_doms) {
# TODO: make sure $_ is not a public suffix
        if ($_ eq $from_dom) {   # strict alignment, requires exact match
            $self->{result}{dkim_aligned} = 'strict';
            $self->{result}{dkim_aligned_domains}{$_} = 'strict';
            next;
        }

        # don't try relaxed if policy specifies strict
        next if $policy->adkim && lc $policy->adkim eq 's';

        # relaxed policy (default): Org. Dom must match a DKIM sig
        if ( $_ eq $org_dom ) {
            $self->{result}{dkim_aligned} = 'relaxed'
                if ! defined $self->{result}{dkim_aligned};
            $self->{result}{dkim_aligned_domains}{$_} = 'relaxed';
        };
    };
    return 1 if $self->{result}{dkim_aligned};
    return;
};

sub is_spf_aligned {
    my ($self, $spf_dom ) = @_;

    if ( ! $spf_dom ) {
        $self->{result}{spf_aligned} = 0;
        return;
    };

    my $from_dom = $self->{result}{from_domain} or croak "from_domain not set!";

    if ($spf_dom eq $from_dom) {
        $self->{result}{spf_aligned} = 'strict';
        return 1;
    }

    # don't try relaxed match if strict policy requested
    return 0 if ($self->policy->aspf && lc $self->policy->aspf eq 's' );

    my $org_dom  = $self->{result}{org_domain}
        || $self->get_organizational_domain() or return 0;

    if ($spf_dom eq $org_dom) {
        $self->{result}{spf_aligned} = 'relaxed';
        return 1;
    }
    return 0;
};

sub is_public_suffix {
    my ($self, $zone) = @_;

    croak "missing zone name!" if ! $zone;

    my $file = $self->{ps_file} || 'share/public_suffix_list';
    my @dirs = qw[ ./ /usr/local/ /usr/ ];
    my $match;
    foreach my $dir ( @dirs ) {
        $match = $dir . $file;
        last if ( -f $match && -r $match );
    };
    if ( ! -r $match ) {
        croak "unable to locate readable public suffix file\n";
    };

    my $fh = IO::File->new( $match, 'r' )
        or croak "unable to open $match for read: $!\n";

    $zone =~ s/\*/\\*/g;   # escape * char
    return 1 if grep {/^$zone/} <$fh>;

    my @labels = split /\./, $zone;
    $zone = join '.', '\*', (@labels)[1 .. scalar(@labels) - 1];

    $fh = IO::File->new( $match, 'r' );  # reopen
    return 1 if grep {/^$zone/} <$fh>;

    return 0;
};

sub has_dns_rr {
    my ($self, $type, $domain) = @_;

    my $matches = 0;
    my $res = $self->get_resolver();
    my $query = $res->query($domain, $type) or return $matches;
    for my $rr ($query->answer) {
        next if $rr->type ne $type;
        $matches++;
    }
    return $matches;
};

sub has_valid_reporting_uri {
    my ($self, $rua) = @_;
    return 1 if 'mailto:' eq lc substr($rua, 0, 7);
    return 0;
}

sub get_organizational_domain {
    my $self = shift;
    my $from_dom = shift || $self->{result}{from_domain}
        or croak "missing from_domain!";

    # 1.  Acquire a "public suffix" list, i.e., a list of DNS domain
    #     names reserved for registrations. http://publicsuffix.org/list/
    #         $self->qp->config('public_suffix_list')

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
        if ( $self->is_public_suffix($tld) ) {
            $greatest = $i + 1;
        }
    }

    if ( $greatest == scalar @labels ) {      # same
        return $self->{result}{org_domain} = $from_dom;
    };

    # 4.  Construct a new DNS domain name using the name that matched
    #     from the public suffix list and prefixing to it the "x+1"th
    #     label from the subject domain. This new name is the
    #     Organizational Domain.
    return $self->{result}{org_domain} = join '.', reverse((@labels)[0 .. $greatest]);
}

sub get_resolver {
    my $self = shift;
    my $timeout = shift || $self->{dns_timeout};
    return $self->{resolver} if $self->{resolver};
    $self->{resolver} = Net::DNS::Resolver->new(dnsrch => 0);
    $self->{resolver}->tcp_timeout($timeout);
    $self->{resolver}->udp_timeout($timeout);
    return $self->{resolver};
}

sub exists_in_dns {
    my ($self, $domain, $org_dom) = @_;
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
    $org_dom ||= $self->get_organizational_domain($domain);
    my @todo = $domain;
    push @todo, $org_dom if $domain ne $org_dom;
    my $matched = 0;
    foreach ( @todo ) {
        last if $matched;
        $matched++ and next if $self->has_dns_rr('MX', $_);
        $matched++ and next if $self->has_dns_rr('NS', $_);
        $matched++ and next if $self->has_dns_rr('A',  $_);
        $matched++ and next if $self->has_dns_rr('AAAA', $_);
    };
    $self->{result}{domain_exists} = 1 if $matched;
    $self->{result}{error} = "not in DNS" if ! $matched;
    return $matched;
}

sub fetch_dmarc_record {
    my ($self, $zone, $org_dom) = @_;

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
    #     DNS domain matching the one found in the RFC5322.From domain in
    #     the message. A possibly empty set of records is returned.
    $self->{is_subdomain} = defined $org_dom ? 0 : 1;
    my @matches = ();
    my $res = $self->get_resolver();
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
    my ($self, $args) = @_;

    my $from_dom = $self->{result}{from_domain} = $args->{from_domain};
    return $from_dom if $from_dom;

    if ( $args->{from_header} ) {
        $from_dom = $self->{result}{from_domain}
            = $self->get_dom_from_header( $args->{from_header} );
    };
    return $from_dom if $from_dom;

    if ( ! $args->{from_domain} && ! $args->{from_header} ) {
        $self->{result}{error} = "request did not define from_domain or from_header";
        return;
    };

    $self->{result}{error} = "unable to determine from domain";
    return;
};

sub get_dom_from_header {
    my $self = shift;
    my $header = shift or croak "no header!";

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
    return $from_dom;
}

sub external_report {
    my $self = shift;
# TODO:
    return;
};

sub policy {
    my $self = shift;
    return $self->{policy} if defined $self->{policy};
    return $self->{policy} = Mail::DMARC::Policy->new();
};

sub verify_external_reporting {
    my $self = shift;
# TODO
    return;
}

1;
