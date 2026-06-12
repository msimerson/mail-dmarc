package Mail::DMARC::PurePerl;
our $VERSION = '1.20260612';
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC';

sub init {
    my $self = shift;
    $self->is_subdomain(0);
    $self->{header_from} = undef;
    $self->{header_from_raw} = undef;
    $self->{envelope_to} = undef;
    $self->{envelope_from} = undef;
    $self->{source_ip} = undef;
    $self->{sender} = undef;
    $self->{policy} = undef;
    $self->{result} = undef;
    $self->{report} = undef;
    $self->{spf} = undef;
    $self->{dkim} = undef;
    $self->{_tw_cache} = {};
    return;
}

sub validate {
    my $self   = shift;
    my $policy = shift;

    $self->result->result('fail');        # set a couple
    $self->result->disposition('none');   # defaults

    # 11.2.1 Extract RFC5322.From domain
    my $from_dom = $self->get_from_dom() or return $self->result;

    # 9.6. reject email if the domain appears to not exist
    $self->exists_in_dns() or return $self->result;

    $policy ||= $self->discover_policy();  # 11.2.2 Query DNS for DMARC policy
    if (!$policy) {
        # RFC7489 section 4.3 step 8:
        #  If a policy is found, it is combined with the Author's domain
        #  and the SPF and DKIM results to produce a DMARC policy result (a
        #  "pass" or "fail")
        # Hence, if no (valid) policy has been found, produce "none" instead.
        $self->result->result('none');
        return $self->result;
    }

    #   3.5 Out of Scope  DMARC has no "short-circuit" provision, such as
    #         specifying that a pass from one authentication test allows one
    #         to skip the other(s). All are required for reporting.

    eval { $self->is_dkim_aligned; };  # 11.2.3. DKIM signature verification checks
    eval { $self->is_spf_aligned;  };  # 11.2.4. SPF validation checks
    my $aligned = $self->is_aligned(); # 11.2.5. identifier alignment checks

    if ($self->config->{report_store}{auto_save}) {
        eval { $self->save_aggregate(); };
    }

    return $self->result if $aligned;

    # Determine if the from domain is a non-existent subdomain (for np tag)
    my $is_sub     = $self->is_subdomain;
    my $sub_exists = !$is_sub
        || !defined $policy->np
        || $self->_subdomain_exists_in_dns($from_dom);

    my $effective_p;
    if ( $is_sub && !$sub_exists && defined $policy->np ) {
        # RFC 9989 §4.7 np tag: policy for non-existent subdomains
        $effective_p = $policy->np;
    }
    elsif ( defined $policy->sp
        && $self->result->published
        && $self->result->published->domain ne $from_dom )
    {
        $effective_p = $policy->sp;
    }
    else {
        $effective_p = $policy->p;
    }
    $effective_p //= 'none';

    # RFC 9989 4.7 t tag: testing mode, apply one severity level lower
    if ( defined $policy->t && lc( $policy->t ) eq 'y' ) {
        my $tested =
              ( lc($effective_p) eq 'reject' )     ? 'quarantine'
            : ( lc($effective_p) eq 'quarantine' ) ? 'none'
            :                                        $effective_p;
        if ( $tested ne $effective_p ) {
            $effective_p = $tested;
            $self->result->reason(
                type    => 'other',
                comment => 'policy testing mode (t=y)'
            );
        }
    }

    # RFC 9989: pct tag is deprecated and MUST be ignored

    # Apply policy. Emails that fail the DMARC mechanism check are
    # disposed of in accordance with the discovered DMARC policy.
    if ( lc $effective_p eq 'none' ) {
        return $self->result;
    }

    return $self->result if $self->is_whitelisted;

    $self->result->disposition($effective_p);
    return $self->result;
}

sub save_aggregate {
    my ( $self ) = @_;

    my $pol;
    eval { $pol = $self->result->published; };
    if ( $pol && $self->has_valid_reporting_uri($pol->rua) ) {
        my @valid_report_uris = $self->get_valid_reporting_uri($pol->rua);

        my $filtered_report_uris = join( ',',
            map { $_->{'uri'} . ( ( $_->{'max_bytes'} > 0 ) ? ( '!' . $_->{'max_bytes'} ) : q{} ) }
                @valid_report_uris
        );

        $self->result->published->rua( $filtered_report_uris );

        return $self->SUPER::save_aggregate();
    }
    return;
}

sub discover_policy {
    my $self     = shift;
    my $from_dom = shift || $self->header_from or croak;
    print "Header From: $from_dom\n" if $self->verbose;

    # RFC 9989 4.10: DNS Tree Walk replaces PSL-based org domain lookup
    my ( $record_str, $org_dom, $at_dom ) = $self->tree_walk($from_dom);
    # Fall back to PSL when no DMARC records exist for org domain determination
    $org_dom //= $self->_psl_organizational_domain($from_dom);
    $self->is_subdomain( $org_dom eq $from_dom ? 0 : 1 );

    if ( !$record_str ) {
        $self->result->result('none');
        $self->result->reason( type => 'other', comment => 'no policy' )
            if !@{ $self->result->reason };
        return;
    }

    my $policy;
    my $policy_str = "domain=$at_dom;" . $record_str;
    eval { $policy = $self->policy($policy_str) };
    if ($@) {
        $self->result->reason(
            type    => 'other',
            comment => "policy parse error: $@"
        );
        return;
    }
    return unless $policy;
    $self->result->published($policy);

    # If a retrieved policy record does not contain a valid "p" tag, or
    # contains an "sp"/"np" tag that is not valid, then:
    my $p_invalid  = $policy->p  && !$policy->is_valid_p( $policy->p );
    my $sp_invalid = defined $policy->sp && !$policy->is_valid_p( $policy->sp );
    my $np_invalid = defined $policy->np && !$policy->is_valid_p( $policy->np );

    # psd=y records are not required to have p=
    my $is_psd = defined $policy->psd && lc( $policy->psd ) eq 'y';

    if ( ( !$policy->p && !$is_psd ) || $p_invalid || $sp_invalid || $np_invalid ) {
        if (   !$policy->rua
            || !$self->has_valid_reporting_uri( $policy->rua ) )
        {
            $self->result->reason( type => 'other', comment => "no valid rua" );
            return;
        }
        $policy->v('DMARC1');
        $policy->p('none');
    }

    # psd=y records reach here without p= value, default to 'none' so all
    # downstream consumers see a concrete value.
    $policy->p('none') if !$policy->p;

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
    return 0;
}

sub is_dkim_aligned {
    my $self = shift;

    $self->result->dkim('fail');    # our 'default' result
    $self->get_dkim_pass_sigs() or return;

    # 11.2.3 Perform DKIM signature verification checks.  A single email may
    #        contain multiple DKIM signatures.  The results MUST include the
    #        value of the "d=" tag from all DKIM signatures that validated.

    my $from_dom = $self->header_from or croak "header_from not set!";
    my $policy   = $self->policy      or croak "no policy!?";
    my $from_org = $self->get_organizational_domain();

    # Required in report: DKIM-Domain, DKIM-Identity, DKIM-Selector
    foreach my $dkim_ref ( $self->get_dkim_pass_sigs() ) {
        my $dkim_dom = lc $dkim_ref->{domain};

        my $dkmeta = {
            domain   => $dkim_ref->{domain},
            selector => $dkim_ref->{selector},
            identity => '',                      # TODO, what is this?
        };

        if ( $dkim_dom eq $from_dom ) { # strict alignment requires exact match
            $self->result->dkim('pass');
            $self->result->dkim_align('strict');
            $self->result->dkim_meta($dkmeta);
            last;
        }

        # don't try relaxed if policy specifies strict
        next if $policy->adkim && 's' eq lc $policy->adkim;

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
    return 1 if 'pass' eq lc $self->result->dkim;
    return;
}

sub is_spf_aligned {
    my $self    = shift;
    my $spf_dom = shift;

    if ( !$spf_dom && !$self->spf ) { croak "missing SPF!"; }

    my $from_dom = lc $self->header_from or croak "header_from not set!";
    my $from_org = $self->get_organizational_domain($from_dom);

    $self->result->spf('fail');

    my @spf_results;
    if ($spf_dom) {
        push @spf_results, { domain => lc $spf_dom, result => 'pass', scope => 'mfrom' };
    }
    else {
        my @all_results = @{ $self->spf };
        # RFC 7489 §4.3.2: only RFC5321.MailFrom (mfrom) is used for DMARC SPF
        # alignment. EHLO/HELO is not used. Results with no scope specified are
        # treated as mfrom for backward compatibility.
        @spf_results = grep {
            !defined $_->{scope} || lc $_->{scope} ne 'helo'
        } @all_results;
    }

    foreach my $res (@spf_results) {
        next if lc $res->{result} ne 'pass';
        my $s_dom = lc $res->{domain};

        if ( $s_dom eq $from_dom ) {
            $self->result->spf('pass');
            $self->result->spf_align('strict');
            return 1;
        }

        # don't try relaxed match if strict policy requested
        next if $self->policy->aspf && 's' eq lc $self->policy->aspf;

        if ( $self->get_organizational_domain($s_dom) eq $from_org ) {
            $self->result->spf('pass');
            $self->result->spf_align('relaxed');
            # Don't return, we might find a strict match later. DMARC just
            # needs one, for reporting it's nice to have the best match
        }
    }

    return 1 if $self->result->spf eq 'pass';
    return 0;
}

sub is_whitelisted {
    my $self = shift;
    my $s_ip = shift || $self->source_ip;
    return if ! defined $s_ip;
    if ( ! $self->{_whitelist} ) {
        my $white_file = $self->config->{smtp}{whitelist} or return;
        return if ! -f $white_file || ! -r $white_file;
        foreach my $line ( split /\n/, $self->slurp($white_file) ) {
            next if $line =~ /^#/; # ignore comments
            my ($lip,$reason) = split /\s+/, $line, 2;
            next if not defined $lip;
            $self->{_whitelist}{$lip} = $reason;
        };
    };
    return if ! $self->{_whitelist}{$s_ip};

    my ($type, $comment) = split /\s+/, $self->{_whitelist}{$s_ip}, 2;
    # Validate type against RFC 7489 PolicyOverrideType enum
    my @valid_reason_types = qw/ forwarded sampled_out trusted_forwarder mailing_list local_policy other /;
    if ( !$type || !grep { $_ eq lc $type } @valid_reason_types ) {
        $type = 'other';
    }
    $self->result->disposition('none');
    $self->result->reason(
            type => $type,
            ($comment && $comment =~ /\S/ ? ('comment' => $comment) : () ),
            );
    return $type;
}

sub has_valid_reporting_uri {
    my ( $self, $rua ) = @_;
    my @valid_reporting_uris = $self->get_valid_reporting_uri( $rua );
    return scalar @valid_reporting_uris;
}

sub get_valid_reporting_uri {
    my ( $self, $rua ) = @_;
    return unless $rua;
    my $recips_ref = $self->report->uri->parse($rua);
    my @has_permission;
    foreach my $uri_ref (@$recips_ref) {
        if ( !$self->external_report( $uri_ref->{uri} ) ) {
            push @has_permission, $uri_ref;
            next;
        }
        my $ext = $self->verify_external_reporting($uri_ref);
        push @has_permission, $uri_ref if $ext;
    }
    return @has_permission;
}

sub get_dkim_pass_sigs {
    my $self = shift;

    my $dkim_sigs = $self->dkim or return ();    # message not signed

    if ( 'ARRAY' ne ref $dkim_sigs ) {
        croak "dkim needs to be an array reference!";
    }

    return grep { 'pass' eq lc $_->{result} } @$dkim_sigs;
}

sub tree_walk {
    my ( $self, $from_dom ) = @_;
    $from_dom = lc $from_dom;

    return @{ $self->{_tw_cache}{$from_dom} }
        if $self->{_tw_cache}{$from_dom};

    # RFC 9989 4.10 DNS Tree Walk: walk up the DNS hierarchy from
    # the author domain, querying _dmarc.<target> at each level.
    # Stop when a record with psd=n (org domain anchor) or psd=y (PSD)
    # is found, or after 8 queries, or when no labels remain.

    my @labels      = split /\./, $from_dom;
    my $target      = $from_dom;
    my $query_count = 0;

    # policy_record / at_dom: FIRST record found (most specific, author domain wins)
    # org_dom: domain of the last record found, or the psd=n anchor
    # prev_target: target queried one step before the current one (one label
    #   longer); when a psd=y PSD is found, that child is the Organizational Domain
    my ( $policy_record, $at_dom, $org_dom, $prev_target );

    while ( $query_count < 8 && scalar @labels > 0 ) {
        $query_count++;
        my $query = $self->get_resolver->send( "_dmarc.$target", 'TXT' );
        if ($query) {
            my @matches;
            for my $rr ( $query->answer ) {
                next if $rr->type ne 'TXT';
                next if 'v=dmarc1' ne lc substr( $rr->txtdata, 0, 8 );
                push @matches, join( '', $rr->txtdata );
            }
            if ( scalar @matches == 1 ) {
                my $rec = $matches[0];
                my $pol = eval { $self->policy->parse("domain=$target;$rec") };
                if ($pol) {
                    # Author domain takes precedence: save only the first record found
                    if ( !defined $policy_record ) {
                        $policy_record = $rec;
                        $at_dom        = $target;
                    }
                    my $psd_val = defined $pol->psd ? lc $pol->psd : 'u';
                    if ( $psd_val eq 'n' ) {
                        # Lucky anchor: this domain is the Organizational Domain
                        print "Tree Walk anchor (psd=n): $target\n"
                            if $self->verbose;
                        my @result = ( $policy_record, $target, $at_dom );
                        $self->{_tw_cache}{$from_dom} = \@result;
                        return @result;
                    }
                    if ( $psd_val eq 'y' ) {
                        # PSD found; org domain is the child one label below it
                        my $below = $prev_target // $from_dom;
                        print "Tree Walk PSD (psd=y): $target, org=$below\n"
                            if $self->verbose;
                        my @result = ( $policy_record, $below, $at_dom );
                        $self->{_tw_cache}{$from_dom} = \@result;
                        return @result;
                    }
                    # psd=u (default): update org_dom candidate, keep walking
                    $org_dom = $target;
                }
            } elsif ( scalar @matches > 1 ) {
                # 9.5. If the remaining set contains multiple records, processing
                #      terminates and the Mail Receiver takes no action.
                $self->result->reason( type => 'other', comment => "too many policies" );
                print "Too many DMARC records\n" if $self->verbose;
                return;
            }
        }

        # Remove leftmost label; apply >=8-label reduction rule (RFC 9989 4.10)
        $prev_target = $target;
        my $n = scalar @labels;
        if ( $n >= 8 ) {
            my $trim = $n - 7;
            splice @labels, 0, $trim;
        }
        else {
            shift @labels;
        }
        $target = join( '.', @labels );
    }

    # Walked to top without a psd=n/y anchor; use last record found as org domain
    my @result = ( $policy_record, $org_dom, $at_dom );
    $self->{_tw_cache}{$from_dom} = \@result;
    return @result;
}

sub get_organizational_domain {
    my $self     = shift;
    my $from_dom = shift || $self->header_from
        or croak "missing header_from!";
    $from_dom = lc $from_dom;

    my ( undef, $org_dom ) = $self->tree_walk($from_dom);

    # Fallback: when no DMARC records exist in DNS for this tree, use the PSL
    # to determine the org domain
    if ( !defined $org_dom ) {
        $org_dom = $self->_psl_organizational_domain($from_dom);
    }

    print "Organizational Domain: $org_dom\n" if $self->verbose;
    return $org_dom;
}

sub _psl_organizational_domain {
    my ( $self, $from_dom ) = @_;

    my @labels  = reverse split /\./, lc $from_dom;
    my $greatest = 0;
    for ( my $i = 0; $i <= $#labels; $i++ ) {
        next if !$labels[$i];
        my $tld = join '.', reverse( @labels[ 0 .. $i ] );
        $greatest = $i + 1 if $self->is_public_suffix($tld);
    }
    return $from_dom if $greatest == scalar @labels;
    return join '.', reverse( @labels[ 0 .. $greatest ] );
}

sub _subdomain_exists_in_dns {
    my ( $self, $dom ) = @_;
    # RFC 9989 4.7: a subdomain is non-existent only when DNS consistently
    # returns NXDOMAIN. NOERROR/NODATA means the name exists but lacks that
    # record type. Timeouts and other errors are treated conservatively as
    # existing.
    my $got_response = 0;
    for my $type (qw/ A AAAA MX NS /) {
        my $q = $self->get_resolver->send( $dom, $type );
        next unless $q;
        return 1 if $q->header->rcode ne 'NXDOMAIN';  # NOERROR/NODATA or error → exists
        $got_response = 1;
    }
    return $got_response ? 0 : 1;
}

sub exists_in_dns {
    my $self = shift;
    my $from_dom = shift || $self->header_from or croak "no header_from!";

    # rfc7489 6.6.3
    #   If the set produced by the mechanism above contains no DMARC policy
    #   record (i.e., any indication that there is no such record as opposed
    #   to a transient DNS error), Mail Receivers SHOULD NOT apply the DMARC
    #   mechanism to the message.

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
        $self->result->result('none');
        $self->result->disposition('none');
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
    my @matches = ();
    my $query = $self->get_resolver->send( "_dmarc.$zone", 'TXT' )
        or return (\@matches, $zone);

    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';

        #   2.  Records that do not start with a "v=" tag that identifies the
        #       current version of DMARC are discarded.
        next if 'v=dmarc1' ne lc substr( $rr->txtdata, 0, 8 );
        print "\n" . $rr->txtdata . "\n\n" if $self->verbose;
        push @matches, join( '', $rr->txtdata );    # join long records
    }
    if (scalar @matches) {
        return \@matches, $zone;            # found one! (at least)
    }

    #   3.  If the set is now empty, the Mail Receiver MUST query the DNS for
    #       a DMARC TXT record at the DNS domain matching the Organizational
    #       Domain in place of the RFC5322.From domain in the message (if
    #       different).  This record can contain policy to be asserted for
    #       subdomains of the Organizational Domain.
    if ( defined $org_dom ) {                              #  <- recursion break
        if ( $org_dom ne $zone ) {
            return $self->fetch_dmarc_record($org_dom);    #  <- recursion
        }
    }

    return \@matches, $zone;
}

sub get_from_dom {
    my ($self) = @_;
    return $self->header_from if $self->header_from;

    my $header = $self->header_from_raw or do {
        $self->result->reason( type => 'other', comment => "no header_from" );
        return;
    };

    # RFC 7489 §5.6.1: if From contains multiple addresses with different
    # domains, use the Sender header domain. Caller should set $dmarc->sender.
    my @domains;
    while ( $header =~ /\@([\w][\w.-]*)/g ) {
        my $dom = lc $1;
        $dom =~ s/[>;\s,].*$//;
        push @domains, $dom if $dom;
    }
    my %unique_doms = map { $_ => 1 } @domains;
    if ( keys %unique_doms > 1 ) {
        if ( $self->sender ) {
            my $sender_dom = $self->to_ascii_domain( $self->sender );
            return $self->header_from($sender_dom);
        }
        $self->result->result('none');
        $self->result->reason(
            type    => 'other',
            comment => 'multiple RFC5322.From domains; provide Sender header via $dmarc->sender',
        );
        return;
    }

    # Caller can pass in pre-parsed from_dom if this doesn't suit them.
    my ($from_dom) = ( split /@/, $header )[-1]; # grab everything after the @
    ($from_dom) = split /(\s+|>)/, lc $from_dom; # remove trailing cruft
    if ( !$from_dom ) {
        $self->result->reason(
            type    => 'other',
            comment => "invalid header_from: ($header)"
        );
        return;
    }

    # RFC 8616 §6: convert U-labels to A-labels before DNS lookups
    $from_dom = $self->to_ascii_domain($from_dom);

    return $self->header_from($from_dom);
}

sub external_report {
    my ( $self, $uri ) = @_;
    my $dmarc_dom = $self->result->published->domain
        or croak "published policy not tagged!";

    if ( 'mailto' eq $uri->scheme ) {
        my $dest_email = lc $uri->path;
        my ($dest_host) = ( split /@/, $dest_email )[-1];
        if ( $self->get_organizational_domain( $dest_host )
                eq
             $self->get_organizational_domain( $dmarc_dom )
             ) {
            print "$dest_host not external for $dmarc_dom\n" if $self->verbose;
            return 0;
        };
        print "$dest_host is external for $dmarc_dom\n" if $self->verbose;
        return 1;
    }

    if ( $uri->scheme =~ /^https?$/ ) {
        if ( $uri->host eq $dmarc_dom ) {
            print $uri->host ." not external for $dmarc_dom\n" if $self->verbose;
            return 0;
        };
        print $uri->host ." is external for $dmarc_dom\n" if $self->verbose;
        return 1;
    }

    return 1;
}

sub _uri_authority_host {
    my ($uri) = @_;
    my $scheme = $uri->scheme // '';
    if ( $scheme eq 'mailto' ) {
        my $path = $uri->path or return;
        return ( split /@/, $path )[-1];
    }
    elsif ( $scheme =~ /^https?$/ ) {
        return $uri->host;
    }
    return;
}

sub verify_external_reporting {
    my $self = shift;
    my $uri_ref = shift or croak "missing URI";

    #  1.  Extract the host portion of the authority component of the URI.
    #      Call this the "destination host".
    my $dmarc_dom = $self->result->published->domain
        or croak "published policy not tagged!";

    #  1.  Extract the host portion of the authority component of the URI.
    my $dest_host;
    my $scheme = $uri_ref->{uri}->scheme // '';
    if ( $scheme eq 'mailto' ) {
        my $path = $uri_ref->{uri}->path or croak "invalid mailto URI";
        ($dest_host) = ( split /@/, $path )[-1];
    }
    elsif ( $scheme =~ /^https?$/ ) {
        $dest_host = $uri_ref->{uri}->host or croak "invalid $scheme URI";
    }
    else {
        print "\tunsupported URI scheme '$scheme' for external verification\n"
            if $self->verbose;
        return;
    }

    #  2.  Prepend the string "_report._dmarc".
    #  3.  Prepend the domain name from which the policy was retrieved,
    #      after conversion to an A-label if needed.
    my $dest = join '.', $dmarc_dom, '_report._dmarc', $dest_host;

    #  4.  Query the DNS for a TXT record at the constructed name.
    my $query = $self->get_resolver->send( $dest, 'TXT' ) or do {
        print "\tquery for $dest failed\n" if $self->verbose;
        return;
    };

    #  5.  For each record, parse the result...same overall format:
    #      "v=DMARC1" tag is mandatory and MUST appear first in the list.
    my @matches;
    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';

        next if 'v=dmarc1' ne lc substr( $rr->txtdata, 0, 8 );
        my $policy = undef;
        my $dmarc_str = join( '', $rr->txtdata );    # join parts
        eval { $policy = $self->policy->parse($dmarc_str) }; ## no critic (Eval)
        push @matches, $policy ? $policy : $dmarc_str;
    }

    #  6.  If the result includes no TXT resource records...stop
    if ( !scalar @matches ) {
        print "\tno TXT match for $dest\n" if $self->verbose;
        return;
    };

    #  7.  If > 1 TXT resource record remains, external reporting authorized
    #  8.  If a "rua" or "ruf" tag is discovered, replace the
    #      corresponding value with the one found in this record.
    my @overrides = grep { ref $_ && $_->{rua} } @matches;
    foreach my $or (@overrides) {
        my $recips_ref = $self->report->uri->parse( $or->{rua} ) or next;
        # the overriding URI MUST use the same destination host from step 1.
        my $override_host = _uri_authority_host( $recips_ref->[0]{uri} );
        next unless defined $override_host && $override_host eq $dest_host;
        print "found override RUA: $or->{rua}\n" if $self->verbose;
        $self->result->published->rua( $or->{rua} );
    }

    return @matches;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::PurePerl - Pure Perl implementation of DMARC

=head1 VERSION

version 1.20260612

=head1 METHODS

=head2 init

Reset the Mail::DMARC object, preparing it for a fresh request.

=head2 validate

This method does the following:

=over 4

* check if the RFC5322.From domain exists (exists_in_dns)

* query DNS for a DMARC policy (discover_policy)

* check DKIM alignment (is_dkim_aligned)

* check SPF alignment (is_spf_aligned)

* determine DMARC alignment (is_aligned)

* calculate the I<effective> DMARC policy

* apply the DMARC policy (see L<Mail::DMARC::Result>)

=back

=head2 discover_policy

Query the DNS to determine if a DMARC policy exists. When the domain name in the email From header (header_from) is not an Organizational Domain (ex: www.example.com), an attempt is made to determine the O.D. using the Mozilla Public Suffix List. When the O.D. differs from the header_from, a second DNS query is sent to _dmarc.[O.D.].

If a DMARC DNS record is found, it is parsed as a L<Mail::DMARC::Policy> object and returned.

=head2 is_aligned

Determine if this message is DMARC aligned. To pass this test, the message must pass at least one of the alignment test (DKIM or SPF).

=head2 is_dkim_aligned

Determine if a valid DKIM signature in the message is aligned with the message's From header domain. This match can be in strict (exact match) or relaxed (subdomains match) alignment.

=head2 is_spf_aligned

Same as DKIM, but for SPF.

=head2 has_valid_reporting_uri

Check for the presence of a valid reporting URI in the rua or ruf DMARC policy tags.

=head2 get_organizational_domain

From the 2013 DMARC spec, section 4:

  Organizational Domain: ..is the domain that was registered with a domain
  name registrar. Heuristics are used to determine this...

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

Query the DNS for the presence of a DMARC record at the header from domain name and the Organizational Domain name. Returns the discovered DNS record answers.

=head2 get_from_dom

Returns the header_from attribute, if defined.

When header_from is not defined, crudely, and very quickly parse a From header and return the domain name (aka, the header_from domain).

The From header format is defined in RFC 822 and is very complex. The From header can contain multiple email addresses, each with different domains. This method returns the last one. If you want to handle this differently, parse the From header yourself and set header_from.

=head2 external_report

Determine if a report URL is external. If the domain name portion of the URI is not the same as the domain where the DMARC record was discovered, the report address is considered external.

=head2 verify_external_reporting

=head3 8.2.  Verifying External Destinations

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

  1.  Extract the host portion of the authority component of the URI.
      Call this the "destination host".
  2.  Prepend the string "_report._dmarc".
  3.  Prepend the domain name from which the policy was retrieved,
      after conversion to an A-label if needed.
  4.  Query the DNS for a TXT record at the constructed name.
  5.  For each record, parse the result...same overall format:
      "v=DMARC1" tag is mandatory and MUST appear first in the list.
  6.  If the result includes no TXT resource records...stop
  7.  If > 1 TXT resource record remains, external reporting authorized
  8.  If a "rua" or "ruf" tag is discovered, replace the
      corresponding value with the one found in this record.

The overriding URI MUST use the same destination host from the first step.

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
