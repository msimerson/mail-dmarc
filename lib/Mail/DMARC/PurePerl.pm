package Mail::DMARC::PurePerl;
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC';

sub init {
    my $self = shift;
    $self->is_subdomain(0);
    $self->{policy} = undef;
    $self->{result} = undef;
    $self->{report} = undef;
    return;
}

sub validate {
    my $self   = shift;
    my $policy = shift;

    my $from_dom = $self->get_from_dom()  # 11.2.1 Extract RFC5322.From domain
        or return;
    $self->exists_in_dns()    # 9.6. Receivers should reject email if
        or return;            #      the domain appears to not exist
    $policy ||= $self->discover_policy();  # 11.2.2 Query DNS for DMARC policy
    $policy or return;

    #   3.5 Out of Scope  DMARC has no "short-circuit" provision, such as
    #         specifying that a pass from one authentication test allows one
    #         to skip the other(s). All are required for reporting.

    $self->is_dkim_aligned
        ;    # 11.2.3. Perform DKIM signature verification checks
    $self->is_spf_aligned;    # 11.2.4. Perform SPF validation checks
    $self->is_aligned()       # 11.2.5. Conduct identifier alignment checks
        and return 1;

    my $effective_p
        = $self->is_subdomain && defined $policy->sp
        ? $policy->sp
        : $policy->p;

    # 11.2.6 Apply policy.  Emails that fail the DMARC mechanism check are
    #        disposed of in accordance with the discovered DMARC policy of the
    #        Domain Owner.  See Section 6.2 for details.
    if ( lc $effective_p eq 'none' ) {
        $self->result->disposition('none');
        return;
    }

    # 7.1.  Policy Fallback Mechanism
    # If the "pct" tag is present in a policy record, application of policy
    # is done on a selective basis.
    if ( !defined $policy->pct ) {
        $self->result->disposition($effective_p);
        return;
    }

    # The stated percentage of messages that fail the DMARC test MUST be
    # subjected to whatever policy is selected by the "p" or "sp" tag
    if ( int( rand(100) ) >= $policy->pct ) {
        $self->result->disposition('none');
        $self->result->reason( type => 'sampled_out' );
        return;
    }

    # Those that are not thus
    # selected MUST instead be subjected to the next policy lower in terms
    # of severity.  In decreasing order of severity, the policies are
    # "reject", "quarantine", and "none".
    #
    # For example, in the presence of "pct=50" in the DMARC policy record
    # for "example.com", half of the mesages with "example.com" in the
    # RFC5322.From field which fail the DMARC test would be subjected to
    # "reject" action, and the remainder subjected to "quarantine" action.

    $self->result->disposition(
        ( $effective_p eq 'reject' ) ? 'quarantine' : 'none' );
    return;
}

sub discover_policy {
    my $self     = shift;
    my $from_dom = shift || $self->header_from or croak;
    my $org_dom  = $self->get_organizational_domain($from_dom);

    my $e = $self->result;

    # 9.1  Mail Receivers MUST query the DNS for a DMARC TXT record
    my $matches = $self->fetch_dmarc_record( $from_dom, $org_dom );
    return if 0 == scalar @$matches;

    # 9.5. If the remaining set contains multiple records, processing
    #      terminates and the Mail Receiver takes no action.
    if ( scalar @$matches > 1 ) {
        $e->result('fail');
        $e->disposition('none');
        $e->reason( type => 'other', comment => "too many policies" );
        return;
    }

    #   $e->dmarc_rr($matches->[0]);  # why save this?
    my $policy = $self->policy( $matches->[0] ) or return;
    $policy->domain($from_dom);
    $self->result->published($policy);

    # 9.6 If a retrieved policy record does not contain a valid "p" tag, or
    #     contains an "sp" tag that is not valid, then:
    if (   !$policy->p
        || !$policy->is_valid_p( $policy->p )
        || ( defined $policy->sp && !$policy->is_valid_p( $policy->sp ) ) )
    {

        #   A.  if an "rua" tag is present and contains at least one
        #       syntactically valid reporting URI, the Mail Receiver SHOULD
        #       act as if a record containing a valid "v" tag and "p=none"
        #       was retrieved, and continue processing;
        #   B.  otherwise, the Mail Receiver SHOULD take no action.
        if (   !$policy->rua
            || !$self->has_valid_reporting_uri( $policy->rua ) )
        {
            $e->result('fail');
            $e->disposition('none');
            $e->reason( type => 'other', comment => "no valid rua" );
            return;
        }
        $policy->v('DMARC1');
        $policy->p('none');
    }

    return $policy;
}

sub is_aligned {
    my $self = shift;

    # 11.2.5 Conduct identifier alignment checks.  With authentication checks
    #        and policy discovery performed, the Mail Receiver checks if
    #        Authenticated Identifiers fall into alignment as decribed in
    #        Section 4.  If one or more of the Authenticated Identifiers align
    #        with the RFC5322.From domain, the message is considered to pass
    #        the DMARC mechanism check.  All other conditions (authentication
    #        failures, identifier mismatches) are considered to be DMARC
    #        mechanism check failures.

    if (   'pass' eq $self->result->spf
        || 'pass' eq $self->result->dkim )
    {
        $self->result->result('pass');
        $self->result->disposition('none');
        return 1;
    }
    $self->result->result('fail');
    return 0;
}

sub is_dkim_aligned {
    my $self = shift;

    $self->result->dkim('fail');    # our 'default' result
    my $pass_sigs = $self->get_dkim_pass_sigs() or return;

    # 11.2.3 Perform DKIM signature verification checks.  A single email may
    #        contain multiple DKIM signatures.  The results MUST include the
    #        value of the "d=" tag from all DKIM signatures that validated.

    my $from_dom = $self->header_from or croak "header_from not set!";
    my $policy   = $self->policy      or croak "no policy!?";
    my $from_org = $self->get_organizational_domain();

    # Required in report: DKIM-Domain, DKIM-Identity, DKIM-Selector
    foreach my $dkim_ref ( $self->get_dkim_pass_sigs() ) {
        my $dkim_dom = $dkim_ref->{domain};

        # 4.3.1 make sure $dkim_dom is not a public suffix
        next if $self->is_public_suffix($dkim_dom);

        my $dkmeta = {
            domain   => $dkim_ref->{domain},
            selector => $dkim_ref->{selector},
            identity => '',                      # TODO, what is this?
        };

        if ( $dkim_dom eq $from_dom )
        {    # strict alignment requires exact match
            $self->result->dkim('pass');
            $self->result->dkim_align('strict');
            $self->result->dkim_meta($dkmeta);
            last;
        }

        # don't try relaxed if policy specifies strict
        next if $policy->adkim && lc $policy->adkim eq 's';

        # don't try relaxed if we already got a strict match
        next if 'pass' eq $self->result->dkim;

        # relaxed policy (default): Org. Dom must match a DKIM sig
        my $dkim_org = $self->get_organizational_domain($dkim_dom);
        if ( $dkim_org eq $from_org ) {
            $self->result->dkim('pass');
            $self->result->dkim_align('relaxed');
            $self->result->dkim_meta($dkmeta);
        }
    }
    return 1 if 'pass' eq $self->result->dkim;
    return;
}

sub is_spf_aligned {
    my $self    = shift;
    my $spf_dom = shift;
    if ( !$spf_dom && !$self->spf ) { croak "missing SPF!"; }
    $spf_dom = $self->spf->{domain} if !$spf_dom;
    $spf_dom or croak "missing SPF domain";

    # 11.2.4 Perform SPF validation checks.  The results of this step
    #        MUST include the domain name from the RFC5321.MailFrom if SPF
    #        evaluation returned a "pass" result.

    if ( !$spf_dom ) {
        $self->result->spf('fail');
        return 0;
    }

    my $from_dom = $self->header_from or croak "header_from not set!";

    if ( $spf_dom eq $from_dom ) {
        $self->result->spf('pass');
        $self->result->spf_align('strict');
        return 1;
    }

    # don't try relaxed match if strict policy requested
    if ( $self->policy->aspf && lc $self->policy->aspf eq 's' ) {
        $self->result->spf('fail');
        return 0;
    }

    if ( $self->get_organizational_domain($spf_dom) eq
        $self->get_organizational_domain($from_dom) )
    {
        $self->result->spf('pass');
        $self->result->spf_align('relaxed');
        return 1;
    }
    $self->result->spf('fail');
    return 0;
}

sub has_valid_reporting_uri {
    my ( $self, $rua ) = @_;
    my $recips_ref = $self->report->uri->parse($rua);
    my @has_permission;
    foreach my $uri_ref (@$recips_ref) {
        if ( !$self->external_report( $uri_ref->{uri} ) ) {
            push @has_permission, $uri_ref;
            next;
        }
        my $ext = $self->verify_external_reporting($uri_ref);
        push @has_permission, $ext if $ext;
    }
    return scalar @has_permission;
}

sub get_dkim_pass_sigs {
    my $self = shift;

    my $dkim_sigs = $self->dkim or return ();    # message not signed
    if ( 'ARRAY' ne ref $dkim_sigs ) {
        croak "dkim needs to be an array reference!";
    }

    return grep { $_->{result} eq 'pass' } @$dkim_sigs;
}

sub get_organizational_domain {
    my $self = shift;
    my $from_dom = shift || $self->header_from
        or croak "missing header_from!";

    # 4.1 Acquire a "public suffix" list, i.e., a list of DNS domain
    #     names reserved for registrations. http://publicsuffix.org/list/

    # 4.2 Break the subject DNS domain name into a set of "n" ordered
    #     labels.  Number these labels from right-to-left; e.g. for
    #     "example.com", "com" would be label 1 and "example" would be
    #     label 2.;
    my @labels = reverse split /\./, $from_dom;

    # 4.3 Search the public suffix list for the name that matches the
    #     largest number of labels found in the subject DNS domain.  Let
    #     that number be "x".
    my $greatest = 0;
    for ( my $i = 0; $i <= scalar @labels; $i++ ) {
        next if !$labels[$i];
        my $tld = join '.', reverse( (@labels)[ 0 .. $i ] );

        if ( $self->is_public_suffix($tld) ) {
            $greatest = $i + 1;
        }
    }

    if ( $greatest == scalar @labels ) {    # same
        return $from_dom;
    }

    # 4.4 Construct a new DNS domain name using the name that matched
    #     from the public suffix list and prefixing to it the "x+1"th
    #     label from the subject domain. This new name is the
    #     Organizational Domain.
    return join '.', reverse( (@labels)[ 0 .. $greatest ] );
}

sub exists_in_dns {
    my $self = shift;
    my $from_dom = shift || $self->header_from or croak "no header_from!";

  # 9.6 # If the RFC5322.From domain does not exist in the DNS, Mail Receivers
  #     SHOULD direct the receiving SMTP server to reject the message {R9}.

    my $org_dom = $self->get_organizational_domain($from_dom);
    my @todo    = $from_dom;
    if ( $from_dom ne $org_dom ) {
        push @todo, $org_dom;
        $self->is_subdomain(1);
    }
    my $matched = 0;
    foreach (@todo) {
        last if $matched;
        $matched++ and next if $self->has_dns_rr( 'MX',   $_ );
        $matched++ and next if $self->has_dns_rr( 'NS',   $_ );
        $matched++ and next if $self->has_dns_rr( 'A',    $_ );
        $matched++ and next if $self->has_dns_rr( 'AAAA', $_ );
    }
    if ( !$matched ) {
        $self->result->result('fail');
        $self->result->disposition('reject');
        $self->result->reason(
            type    => 'other',
            comment => "$from_dom not in DNS"
        );
    }
    return $matched;
}

sub fetch_dmarc_record {
    my ( $self, $zone, $org_dom ) = @_;

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
    #     DNS domain matching the one found in the RFC5322.From domain in
    #     the message. A possibly empty set of records is returned.
    $self->is_subdomain( defined $org_dom ? 0 : 1 );
    my @matches = ();
    my $query = $self->get_resolver->send( "_dmarc.$zone", 'TXT' )
        or return \@matches;
    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';

        #   2.  Records that do not start with a "v=" tag that identifies the
        #       current version of DMARC are discarded.
        next if 'v=dmarc1' ne lc substr( $rr->txtdata, 0, 8 );
        push @matches, join( '', $rr->txtdata );    # join long records
    }
    return \@matches if scalar @matches;            # found one! (at least)

    #   3.  If the set is now empty, the Mail Receiver MUST query the DNS for
    #       a DMARC TXT record at the DNS domain matching the Organizational
    #       Domain in place of the RFC5322.From domain in the message (if
    #       different).  This record can contain policy to be asserted for
    #       subdomains of the Organizational Domain.
    if ( defined $org_dom ) {    #  <- recursion break
        if ( $org_dom ne $zone ) {
            return $self->fetch_dmarc_record($org_dom);    #  <- recursion
        }
    }

    $self->result->result('fail');
    $self->result->disposition('none');
    $self->result->reason( type => 'other', comment => 'no policy' );
    return \@matches;
}

sub get_from_dom {
    my ($self) = @_;

    if ( !$self->header_from ) {
        return $self->get_dom_from_header();
    }

    return $self->header_from;
}

sub get_dom_from_header {
    my $self   = shift;
    my $e      = $self->result;
    my $header = $self->header_from_raw or do {
        $e->result('fail');
        $e->disposition('none');
        $e->reason( type => 'other', comment => "no header_from" );
        return;
    };

    # Should I do something special with a From field with multiple addresses?
    # Do what if the domains differ? This returns only the last.
    # Caller can pass in pre-parsed from_dom if this doesn't suit them.
    #
    # I care only about the domain. This is way faster than RFC822 parsing

    my ($from_dom) = ( split /@/, $header )[-1]; # grab everything after the @
    ($from_dom) = split /(\s+|>)/, $from_dom;    # remove trailing cruft
    if ( !$from_dom ) {
        $e->result('fail');
        $e->disposition('none');
        $e->reason(
            type    => 'other',
            comment => "invalid header_from: ($header)"
        );
        return;
    }
    return $self->header_from($from_dom);
}

sub external_report {
    my ( $self, $uri ) = @_;
    my $dmarc_dom = $self->result->published->domain
        or croak "published policy not tagged!";

    if ( 'mailto' eq $uri->scheme ) {
        my $dest_email = $uri->path;
        my ($dest_host) = ( split /@/, $dest_email )[-1];
        return 0 if $dest_host eq $dmarc_dom;
    }

    if ( 'http' eq $uri->scheme ) {
        return 0 if $uri->host eq $dmarc_dom;
    }

    return 1;
}

sub verify_external_reporting {
    my $self = shift;
    my $uri_ref = shift or croak "missing URI";

    #  1.  Extract the host portion of the authority component of the URI.
    #      Call this the "destination host".
    my $dmarc_dom = $self->result->published->domain
        or croak "published policy not tagged!";

    my $dest_email = $uri_ref->{uri}->path or croak("invalid URI");
    my ($dest_host) = ( split /@/, $dest_email )[-1];

    #  2.  Prepend the string "_report._dmarc".
    #  3.  Prepend the domain name from which the policy was retrieved,
    #      after conversion to an A-label if needed.
    my $dest = join '.', $dmarc_dom, '_report._dmarc', $dest_host;

    #  4.  Query the DNS for a TXT record at the constructed name.
    my $query = $self->get_resolver->send( $dest, 'TXT' ) or return;

    #  5.  For each record, parse the result...same overall format:
    #      "v=DMARC1" tag is mandatory and MUST appear first in the list.
    my @matches;
    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';

        next if 'v=dmarc1' ne lc substr( $rr->txtdata, 0, 8 );
        my $policy = undef;
        my $dmarc_str = join( '', $rr->txtdata );    # join ports
        eval { $policy = $self->policy->parse($dmarc_str) }; ## no critic (Eval)
        push @matches, $policy ? $policy : $dmarc_str;
    }

    #  6.  If the result includes no TXT resource records...stop
    return if !scalar @matches;

    #  7.  If > 1 TXT resource record remains, external reporting authorized
    #  8.  If a "rua" or "ruf" tag is discovered, replace the
    #      corresponding value with the one found in this record.
    my @overrides = grep { ref $_ && $_->{rua} } @matches;
    foreach my $or (@overrides) {
        my $recips_ref = $self->report->uri->parse( $or->{rua} ) or next;
        if ( ( split /@/, $recips_ref->[0]{uri} )[-1] eq
            ( split /@/, $uri_ref->{uri} )[-1] )
        {
  # the overriding URI MUST use the same destination host from the first step.
            $self->result->published->rua( $or->{rua} );
        }
    }

    return @matches;
}

1;

# ABSTRACT: Pure Perl implementation of DMARC
__END__
sub {}

=head1 METHODS

=head2 init

Resets the Mail::DMARC object, preparing it for a fresh request.

=head2 validate

=head2 discover_policy

=head2 is_aligned

=head2 is_dkim_aligned

=head2 is_spf_aligned

=head2 has_valid_reporting_uri

=head2 get_organizational_domain

=head2 exists_in_dns

Determine if a domain exists, reliably. The DMARC draft says:

  9.6 If the RFC5322.From domain does not exist in the DNS, Mail Receivers
      SHOULD direct the receiving SMTP server to reject the message {R9}.

And in Appendix A.4:

   A common practice among MTA operators, and indeed one documented in
   [ADSP], is a test to determine domain existence prior to any more
   expensive processing.  This is typically done by querying the DNS for
   MX, A or AAAA resource records for the name being evaluated, and
   assuming the domain is non-existent if it could be determined that no
   such records were published for that domain name.

   The original pre-standardization version of this protocol included a
   mandatory check of this nature.  It was ultimately removed, as the
   method's error rate was too high without substantial manual tuning
   and heuristic work.  There are indeed use cases this work needs to
   address where such a method would return a negative result about a
   domain for which reporting is desired, such as a registered domain
   name that never sends legitimate mail and thus has none of these
   records present in the DNS.

I went back to the ADSP (which led me to the ietf-dkim email list where
some 'experts' failed to agree on The Right Way to test domain validity. They
pointed out: MX records aren't mandatory, and A or AAAA aren't reliable.

Some experimentation proved both arguments in real world usage. This module
tests for existence by searching for a MX, NS, A, or AAAA record. Since this
search may be repeated for the Organizational Name, if the NS query fails,
there is no delegation from the TLD. That has proven very reliable.

=head2 fetch_dmarc_record

=head2 get_from_dom

=head2 get_dom_from_header

=head2 external_report

=head3  8.2.  Verifying External Destinations

It is possible to specify destinations for the different reports that
are outside the domain making the request.  This is enabled to allow
domains that do not have mail servers to request reports and have
them go someplace that is able to receive and process them.

Without checks, this would allow a bad actor to publish a DMARC
policy record that requests reports be sent to a victim address, and
then send a large volume of mail that will fail both DKIM and SPF
checks to a wide variety of destinations, which will in turn flood
the victim with unwanted reports.  Therefore, a verification
mechanism is included.

When a Mail Receiver discovers a DMARC policy in the DNS, and the
domain at which that record was discovered is not identical to the
host part of the authority component of a [URI] specified in the
"rua" or "ruf" tag, the following verification steps SHOULD be taken:

=head2 verify_external_reporting

=cut
