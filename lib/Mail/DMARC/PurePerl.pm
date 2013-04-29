package Mail::DMARC::PurePerl;
use strict;
use warnings;

use IO::File;
use Net::DNS::Resolver;

use parent 'Mail::DMARC';

sub new {
    my $self = shift;
    bless {
        dns_timeout   => 5,
        is_subdomain  => undef,
        resolver      => undef,
        p_vals        => {map { $_ => 1 } qw/ none reject quarantine /},
        ps_file       => 'share/public_suffix_list',
    },
    $self;
}

sub is_valid {
    my $self = shift;

    if ( @_ % 2 != 0 ) {
        $self->{result} = "invalid request";
        return;
    };
    my %args = @_;

    # 11.1.  Extract Author Domain
    my $from_dom = $self->get_from_dom( \%args ) or return;
    my $org_dom  = $self->get_organizational_domain($from_dom);

    # 6. Receivers should reject email if the domain appears to not exist
    $self->exists_in_dns($from_dom, $org_dom) or do {
        $self->{result} = "not in DNS: $from_dom";
        return;
    };

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
            from_domain    => $from_dom,
            org_domain     => $org_dom,
            policy         => $policy,
            dkim_doms      => $args{dkim_pass_domains},
            spf_pass_domain=> $args{spf_pass_dom},
            );

    #   6.  Apply policy.  Emails that fail the DMARC mechanism check are
    #       disposed of in accordance with the discovered DMARC policy of the
    #       Domain Owner.  See Section 6.2 for details.
    if ( $self->{is_subdomain} && defined $policy->{sp} ) {
        return 1 if lc $policy->{sp} eq 'none';
    };
    return 1 if lc $policy->{p} eq 'none';

    my $pct = $policy->{pct} || 100;
    if ( $pct != 100 && int(rand(100)) >= $pct ) {
        warn "fail, tolerated, policy, sampled out";
        return;
    };

    warn "failed DMARC policy\n";
    return;
}

sub discover_policy {
    my ($self, $from_dom, $org_dom) = @_;

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record...
    my $matches = $self->fetch_dmarc_record($from_dom, $org_dom) or do {
        $self->{result} = "no DMARC records";
        return;
    };

    # 4.  Records that do not include a "v=" tag that identifies the
    #     current version of DMARC are discarded.
    my @matches = grep /^v=DMARC1/i, @$matches;
    if (0 == scalar @matches) {
        $self->{result} = "no valid DMARC record for $from_dom";
        return;
    }

    # 5.  If the remaining set contains multiple records, processing
    #     terminates and the Mail Receiver takes no action.
    if (@matches > 1) {
        $self->{result} = "too many DMARC records";
        return;
    }

    # 6.  If a retrieved policy record does not contain a valid "p" tag, or
    #     contains an "sp" tag that is not valid, then:
    my $policy = $self->parse_policy($matches[0]);
    if (!$self->is_valid_policy($policy->{p})
            || (defined $policy->{sp} && ! $self->is_valid_policy($policy->{sp}) ) ) {

        #   A.  if an "rua" tag is present and contains at least one
        #       syntactically valid reporting URI, the Mail Receiver SHOULD
        #       act as if a record containing a valid "v" tag and "p=none"
        #       was retrieved, and continue processing;
        #   B.  otherwise, the Mail Receiver SHOULD take no action.
        my $rua = $policy->{rua};
        if (!$rua || !$self->has_valid_reporting_uri($rua)) {
            $self->{result} = "no valid reporting rua";
            return;
        }
        $policy->{v} = 'DMARC1';
        $policy->{p} = 'none';
    }

    return $policy;
}

sub is_aligned {
    my $self = shift;
    die "invalid arguments to is_aligned\n" if @_ % 2 != 0;
    my %args = @_;

    my $from_dom = $args{from_domain} or die "missing from domain param\n";
    my $org_dom  = $args{org_domain} || $self->get_organizational_domain( $from_dom );
    my $policy   = $args{policy} || $self->discover_policy( $from_dom, $org_dom );
    my $spf_dom  = $args{spf_pass_domain} || '';
    my $dkim_doms= $args{dkim_pass_domains} || [];

    #   5.  Conduct identifier alignment checks.  With authentication checks
    #       and policy discovery performed, the Mail Receiver checks if
    #       Authenticated Identifiers fall into alignment as decribed in
    #       Section 4.  If one or more of the Authenticated Identifiers align
    #       with the RFC5322.From domain, the message is considered to pass
    #       the DMARC mechanism check.  All other conditions (authentication
    #       failures, identifier mismatches) are considered to be DMARC
    #       mechanism check failures.

    foreach (@$dkim_doms) {
        if ($_ eq $from_dom) {   # strict alignment, requires exact match
            $self->{result} = "DKIM aligned";
            return 1;
        }
        next if $policy->{adkim} && lc $policy->{adkim} eq 's'; # strict pol.
        # relaxed policy (default): Org. Dom must match a DKIM sig
        if ( $_ eq $org_dom ) {
            $self->{result} = "DKIM aligned, relaxed";
            return 1;
        };
    }

    return 0 if ! $spf_dom;
    if ($spf_dom eq $from_dom) {
        $self->{result} = "SPF aligned";
        return 1;
    }
    return 0 if ($policy->{aspf} && lc $policy->{aspf} eq 's' ); # strict pol
    if ($spf_dom eq $org_dom) {
        $self->{result} = "SPF aligned, relaxed";
        return 1;
    }

    return 0;
};

sub is_public_suffix {
    my ($self, $zone) = @_;

    my $file = $self->{ps_file} || 'share/public_suffix_list';
    my @dirs = qw[ ./ /usr/local/ /usr/ ];
    my $match;
    foreach my $dir ( @dirs ) {
        $match = $dir . $file;
        last if ( -f $match && -r $match );
    };
    if ( ! -r $match ) {
        die "unable to locate readable public suffix file\n";
    };

    my $fh = new IO::File $match, 'r'
        or die "unable to open $match for read: $!\n";

    $zone =~ s/\*/\\*/g;   # escape * char
    return 1 if grep /^$zone/, <$fh>;

    my @labels = split /\./, $zone;
    $zone = join '.', '\*', (@labels)[1 .. length(@labels)];

    $fh = new IO::File $match, 'r';  # reopen
    return 1 if grep /^$zone/, <$fh>;

    return 0;
};

sub has_dns_rr {
    my ($self, $type, $domain) = @_;

    my $matches = 0;
    my $res = $self->get_resolver();
    my $query = $res->query($domain, $type) or do {
        if ($res->errorstring eq 'NXDOMAIN') {
#warn "fail, non-existent domain: $domain\n";
            return $matches;
        }
        return if $res->errorstring eq 'NOERROR';
#warn "error, looking up $domain: " . $res->errorstring . "\n";
        return $matches;
    };
    for my $rr ($query->answer) {
        next if $rr->type ne $type;
        $matches++;
    }
    if (0 == $matches) {
        warn "no $type records for $domain";
    }
    return $matches;
};

sub is_valid_policy {
    my ($self, $policy) = @_;
    return 1 if $self->{p_vals}{$policy};
    return 0;
}


sub has_valid_reporting_uri {
    my ($self, $rua) = @_;
    return 1 if 'mailto:' eq lc substr($rua, 0, 7);
    return 0;
}

sub get_organizational_domain {
    my ($self, $from_dom) = @_;

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

        #warn "i: $i -  tld: $tld\n";
        if ( $self->is_public_suffix($tld) ) {
            $greatest = $i + 1;
        }
    }

    return $from_dom if $greatest == scalar @labels;    # same

    # 4.  Construct a new DNS domain name using the name that matched
    #     from the public suffix list and prefixing to it the "x+1"th
    #     label from the subject domain. This new name is the
    #     Organizational Domain.
    return join '.', reverse((@labels)[0 .. $greatest]);
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
# MX records aren't mandatory, and A|AAAA as fallback aren't reliable.
#
# Some experimentation proved both cases in real world usage. Instead, I test
# existence by searching for a MX, NS, A, or AAAA record. Since this search
# is repeated for the Organizational Name, if the NS query fails, there's no
# delegation from the TLD. That's proven very reliable.
    $org_dom ||= $self->get_organizational_domain($domain);
    my @todo = $domain;
    push @todo, $org_dom if $domain ne $org_dom;
    foreach ( @todo ) {
        return 1 if $self->has_dns_rr('MX', $_);
        return 1 if $self->has_dns_rr('NS', $_);
        return 1 if $self->has_dns_rr('A',  $_);
        return 1 if $self->has_dns_rr('AAAA', $_);
    };
    return 0;
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

#warn "no policy for $zone\n";
    return \@matches;
}

sub get_from_dom {
    my ($self, $args) = @_;

    my $from_dom = $args->{from_domain};
    return $from_dom if $from_dom;

    if ( $args->{from_header} ) {
        $from_dom = $self->get_dom_from_header( $args->{from_header} );
    };
    return $from_dom if $from_dom;

    if ( ! $args->{from_domain} && ! $args->{from_header} ) {
        $self->{result} = "missing from arguments in request";
        return;
    };

    $self->{result} = "unable to determine from domain";
    return;
};

sub get_dom_from_header {
    my $self = shift;
    my $header = shift or die "no header!";

# TODO: consider how to handle a From field with multiple addresses. This
# currently returns only the last one.
    if ( 'from:' eq lc substr($header,0,5) ) { # if From: prefix is present
        $header = substr $header, 6;           # remove it
    };

    my ($from_dom) = (split /@/, $header)[-1]; # grab everything after the @
    ($from_dom) = split /\s+/, $from_dom;      # remove any trailing cruft
    chomp $from_dom;                           # remove \n
    chop $from_dom if '>' eq substr($from_dom, -1, 1); # remove closing >
#warn "info, from_dom is $from_dom\n";
    return $from_dom;
}

sub parse_policy {
    my ($self, $str) = @_;
    $str =~ s/\s//g;                             # remove all whitespace
    my %dmarc = map { split /=/, $_ } split /;/, $str;
    return \%dmarc;
}

sub external_report {
    my $self = shift;

};

sub verify_external_reporting {
    my $self = shift;


}

1;
