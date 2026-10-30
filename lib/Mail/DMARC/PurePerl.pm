package Mail::DMARC::PurePerl;
our $VERSION = '2.20260827';
use strict;
use warnings;
use feature 'signatures';
use feature 'try';
no warnings 'experimental::try';    ## no critic (ProhibitNoWarnings)

use Carp;

use parent 'Mail::DMARC';

sub init($self) {
    $self->is_subdomain(0);
    $self->{header_from}     = undef;
    $self->{header_from_raw} = undef;
    $self->{envelope_to}     = undef;
    $self->{envelope_from}   = undef;
    $self->{source_ip}       = undef;
    $self->{sender}          = undef;
    $self->{policy}          = undef;
    $self->{result}          = undef;
    $self->{report}          = undef;
    $self->{spf}             = undef;
    $self->{dkim}            = undef;
    $self->{_tw_cache}       = {};
    $self->{_tw_error}       = {};
    $self->{_author_domains} = undef;
    return;
}

sub validate( $self, $policy = undef ) {
    $self->result->result('fail');         # set a couple
    $self->result->disposition('none');    # defaults

    # 11.2.1 Extract RFC5322.From domain
    my $from_dom = $self->get_from_dom();
    if ( !$from_dom ) {
        my $authors = delete $self->{_author_domains} or return $self->result;
        return $self->_validate_each_author( $policy, @$authors );
    }

    if ($policy) {
        $self->{policy} = $policy;
        $self->result->published($policy) if $policy->domain;
    }
    else {
        $policy = $self->discover_policy();    # 11.2.2 Query DNS for DMARC policy
    }
    return $self->_dns_temperror($from_dom) if $self->{_tw_error}{$from_dom};
    if ( !$policy ) {

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

    try { $self->is_dkim_aligned; } catch ($e) { };   # 11.2.3. DKIM signature verification checks
    try { $self->is_spf_aligned; } catch ($e) { };    # 11.2.4. SPF validation checks
    my $aligned = $self->is_aligned();    # 11.2.5. identifier alignment checks

    if ( $self->config->{report_store}{auto_save} ) {
        try { $self->save_aggregate(); } catch ($e) { };
    }

    return $self->result if $aligned;

    my $effective_p = $self->_assessment_policy( $policy, $from_dom ) // 'none';

    # RFC 9989 4.7 t tag: testing mode, apply one severity level lower
    if ( defined $policy->t && lc( $policy->t ) eq 'y' ) {
        my $tested
            = ( lc($effective_p) eq 'reject' )     ? 'quarantine'
            : ( lc($effective_p) eq 'quarantine' ) ? 'none'
            :                                        $effective_p;
        if ( $tested ne $effective_p ) {
            $effective_p = $tested;
            $self->result->reason( type => 'policy_test_mode' );
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

# RFC 9989 4.10.1
sub _assessment_policy( $self, $policy, $from_dom ) {
    my $policy_dom = $policy->domain // $from_dom;
    return $policy->p if $policy_dom eq $from_dom;
    return $policy->np
        if defined $policy->np && !$self->_author_domain_exists($from_dom);
    return $policy->sp // $policy->p;
}

# RFC 9989 5.3.6
sub _dns_temperror( $self, $from_dom ) {
    $self->result->result('temperror');
    $self->result->disposition('none');
    $self->result->reason(
        type    => 'other',
        comment => "DNS error: $self->{_tw_error}{$from_dom}"
    );
    return $self->result;
}

my $max_author_domains = 5;
my %disposition_rank   = ( none => 0, quarantine => 1, reject => 2 );
my %result_rank        = ( pass => 0, none => 1, temperror => 2, fail => 3 );

# RFC 9989 11.5; the cap bounds the DNS work a crafted From can cause
sub _validate_each_author( $self, $policy, @authors ) {

    # skipping some would let a sender bury the protected domain among others
    if ( @authors > $max_author_domains ) {
        $self->result->result('permerror');
        $self->result->disposition('none');
        $self->result->reason(
            type    => 'other',
            comment => scalar(@authors)
                . " RFC5322.From domains, over the limit of $max_author_domains"
        );
        return $self->result;
    }

    my $strictest;
    for my $author (@authors) {
        my $one = bless { %$self, map { $_ => undef } qw/ policy result report / },
            ref $self;
        $one->header_from($author);
        $one->validate($policy);
        $strictest = $one
            if !$strictest || _is_stricter( $one->result, $strictest->result );
    }
    %$self = %$strictest;
    return $self->result;
}

sub _is_stricter( $candidate, $current ) {
    my @rank = map {
        [ $disposition_rank{ lc $_->disposition }, $result_rank{ lc $_->result } ]
    } $candidate, $current;
    return ( $rank[0][0] <=> $rank[1][0] || $rank[0][1] <=> $rank[1][1] ) > 0;
}

sub save_aggregate($self) {
    my $pol;
    try {
        $pol = $self->result->published;
    } catch ($e) { };
    if ( $pol && $self->has_valid_reporting_uri( $pol->rua ) ) {
        my @valid_report_uris = $self->get_valid_reporting_uri( $pol->rua );

        my $filtered_report_uris = join(
            ',',
            map {
                $_->{'uri'}
                    . (
                    ( $_->{'max_bytes'} > 0 ) ? ( '!' . $_->{'max_bytes'} ) : q{} )
            } @valid_report_uris
        );

        $self->result->published->rua($filtered_report_uris);

        return $self->SUPER::save_aggregate();
    }
    return;
}

sub discover_policy( $self, $from_dom = undef ) {
    $from_dom ||= $self->header_from;
    croak                            if !$from_dom;
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
    try {
        $policy = $self->policy($policy_str);
    }
    catch ($error) {
        $self->result->reason(
            type    => 'other',
            comment => "policy parse error: $error"
        );
        return;
    }
    return unless $policy;
    $policy->discovery_method('treewalk');
    $self->result->published($policy);

    # psd=y records reach here without p= value, default to 'none' so all
    # downstream consumers see a concrete value.
    $policy->p('none') if !$policy->p;

    return $policy;
}

sub is_aligned($self) {

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

sub is_dkim_aligned($self) {
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

        if ( $dkim_dom eq $from_dom ) {    # strict alignment requires exact match
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

sub is_spf_aligned( $self, $spf_dom = undef ) {

    if ( !$spf_dom && !$self->spf ) { croak "missing SPF!"; }

    my $from_dom = lc $self->header_from or croak "header_from not set!";
    my $from_org = $self->get_organizational_domain($from_dom);

    $self->result->spf('fail');

    my @spf_results;
    if ($spf_dom) {
        push @spf_results,
            { domain => lc $spf_dom, result => 'pass', scope => 'mfrom' };
    }
    else {
        my @all_results = @{ $self->spf };

        # RFC 7489 §4.3.2: only RFC5321.MailFrom (mfrom) is used for DMARC SPF
        # alignment. EHLO/HELO is not used. Results with no scope specified are
        # treated as mfrom for backward compatibility.
        @spf_results = grep { !defined $_->{scope} || lc $_->{scope} ne 'helo' }
            @all_results;
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

sub is_whitelisted( $self, $s_ip = undef ) {
    $s_ip ||= $self->source_ip;
    return if !defined $s_ip;
    if ( !$self->{_whitelist} ) {
        my $white_file = $self->config->{smtp}{whitelist} or return;
        return if !-f $white_file || !-r $white_file;
        foreach my $line ( split /\n/, $self->slurp($white_file) ) {
            next if $line =~ /^#/;    # ignore comments
            my ( $lip, $reason ) = split /\s+/, $line, 2;
            next if not defined $lip;
            $self->{_whitelist}{$lip} = $reason;
        }
    }
    return if !$self->{_whitelist}{$s_ip};

    my ( $type, $comment ) = split /\s+/, $self->{_whitelist}{$s_ip}, 2;

    # Validate type against RFC 7489 PolicyOverrideType enum
    my @valid_reason_types
        = qw/ forwarded sampled_out trusted_forwarder mailing_list local_policy other /;
    if ( !$type || !grep { $_ eq lc $type } @valid_reason_types ) {
        $type = 'other';
    }
    $self->result->disposition('none');
    $self->result->reason(
        type => $type,
        ( $comment && $comment =~ /\S/ ? ( 'comment' => $comment ) : () ),
    );
    return $type;
}

sub has_valid_reporting_uri( $self, $rua ) {
    my @valid_reporting_uris = $self->get_valid_reporting_uri($rua);
    return scalar @valid_reporting_uris;
}

sub get_valid_reporting_uri( $self, $rua ) {
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

sub get_dkim_pass_sigs($self) {
    my $dkim_sigs = $self->dkim or return ();    # message not signed

    if ( 'ARRAY' ne ref $dkim_sigs ) {
        croak "dkim needs to be an array reference!";
    }

    return grep { 'pass' eq lc $_->{result} } @$dkim_sigs;
}

sub tree_walk( $self, $from_dom ) {
    $from_dom = lc $from_dom;
    $from_dom =~ s/\.$//;

    $self->{_tw_cache}{$from_dom} //= [
        $self->_select_from_tree_walk(
            $from_dom, $self->_tree_walk_records($from_dom)
        )
    ];
    return @{ $self->{_tw_cache}{$from_dom} };
}

# RFC 9989 4.10, longest name first
sub _tree_walk_records( $self, $from_dom ) {
    my @labels = split /\./, $from_dom;
    my @found;

    for ( 1 .. 8 ) {
        last if !@labels;
        my $target = join '.', @labels;
        splice @labels, 0, ( @labels >= 8 ? @labels - 7 : 1 );

        my $found = $self->_tree_walk_query($target) or next;
        if ( $found->{error} ) {
            $self->{_tw_error}{$from_dom} = $found->{error};
            return;
        }
        push @found, $found;
        last if $found->{psd} ne 'u';
    }
    return @found;
}

sub _tree_walk_query( $self, $target ) {
    my $resolver = $self->get_resolver;
    my $query    = $resolver->send( "_dmarc.$target", 'TXT' );
    my $rcode    = $query ? $query->header->rcode : $resolver->errorstring;
    return { error => "_dmarc.$target: $rcode" }
        if !$query || $rcode !~ /^(?:NOERROR|NXDOMAIN)$/;

    my @matches;
    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';
        my $txt = join '', $rr->txtdata;
        push @matches, $txt if _is_dmarc_record($txt);
    }

    # RFC 9989 4.10 step 2
    if ( @matches > 1 ) {
        print "Ignoring multiple DMARC records at $target\n" if $self->verbose;
        return;
    }
    return if !@matches;

    my $pol = $self->policy->parse("domain=$target;$matches[0]");
    return {
        domain => $target,
        record => $matches[0],
        psd    => defined $pol->psd ? lc $pol->psd : 'u',
    };
}

sub _select_from_tree_walk( $self, $from_dom, @found ) {
    return ( undef, undef, undef ) if !@found;

    # RFC 9989 4.10.2: the walk stops at psd=n/y, so only $last can carry one
    my $last    = $found[-1];
    my $org_dom = $last->{domain};
    if ( $last->{psd} eq 'y' && $last->{domain} ne $from_dom ) {
        $org_dom = _one_label_below( $from_dom, $last->{domain} );
    }
    print "Tree Walk Organizational Domain: $org_dom\n" if $self->verbose;

    my %by_domain = map { $_->{domain} => $_ } @found;

    # the >=8-label shortcut can skip the Organizational Domain
    if (   !$by_domain{$org_dom}
        && $org_dom ne $from_dom
        && _label_count($org_dom) > 7 )
    {
        my $found = $self->_tree_walk_query($org_dom);
        if ( $found && $found->{error} ) {
            $self->{_tw_error}{$from_dom} = $found->{error};
        }
        elsif ($found) {
            $by_domain{$org_dom} = $found;
        }
    }

    # RFC 9989 4.10.1
    my $policy = $by_domain{$from_dom} // $by_domain{$org_dom} // $last;

    return ( $policy->{record}, $org_dom, $policy->{domain} );
}

# laxer than RFC 9989 4.7 about case, quotes, and whitespace (#39)
sub _is_dmarc_record($txt) {
    return $txt =~ /^\s*"?\s*v\s*=\s*DMARC1\s*(?:[;,"]|$)/i;
}

sub _label_count($dom) {
    return 1 + ( $dom =~ tr/.// );
}

sub _one_label_below( $from_dom, $ancestor ) {
    my $depth  = 1 + _label_count($ancestor);
    my @labels = split /\./, $from_dom;
    return join '.', @labels[ -$depth .. -1 ];
}

sub get_organizational_domain( $self, $from_dom = undef ) {
    $from_dom ||= $self->header_from;
    croak "missing header_from!" if !$from_dom;
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

sub _psl_organizational_domain( $self, $from_dom ) {
    my @labels   = reverse split /\./, lc $from_dom;
    my $greatest = 0;
    for ( my $i = 0; $i <= $#labels; $i++ ) {
        next if !$labels[$i];
        my $tld = join '.', reverse( @labels[ 0 .. $i ] );
        $greatest = $i + 1 if $self->is_public_suffix($tld);
    }
    return $from_dom if $greatest == @labels;
    return join '.', reverse( @labels[ 0 .. $greatest ] );
}

sub _dns_name_exists( $self, $dom ) {

    # RFC 9989 3.2.13: a name is non-existent only when DNS consistently
    # returns NXDOMAIN. NOERROR/NODATA means the name exists but lacks that
    # record type. Timeouts and other errors are treated conservatively as
    # existing.
    my $got_response = 0;
    for my $type (qw/ A AAAA MX NS /) {
        my $q = $self->get_resolver->send( $dom, $type );
        next unless $q;
        return 1
            if $q->header->rcode ne 'NXDOMAIN';   # NOERROR/NODATA or error → exists
        $got_response = 1;
    }
    return $got_response ? 0 : 1;
}

sub _author_domain_exists( $self, $dom ) {
    return $self->_dns_name_exists($dom);
}

sub exists_in_dns( $self, $from_dom = undef ) {
    $from_dom ||= $self->header_from;
    croak "no header_from!" if !$from_dom;

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
        $matched = 1 if $self->_dns_name_exists($_);
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

sub fetch_dmarc_record( $self, $zone, $org_dom = undef ) {

    # 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
    #     DNS domain matching the one found in the RFC5322.From domain in
    #     the message. A possibly empty set of records is returned.
    my @matches = ();
    my $query   = $self->get_resolver->send( "_dmarc.$zone", 'TXT' )
        or return ( \@matches, $zone );

    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';

        #   2.  Records that do not start with a "v=" tag that identifies the
        #       current version of DMARC are discarded.
        my $txt = join '', $rr->txtdata;
        next if !_is_dmarc_record($txt);
        print "\n$txt\n\n" if $self->verbose;
        push @matches, $txt;
    }
    if (@matches) {
        return \@matches, $zone;                    # found one! (at least)
    }

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

    return \@matches, $zone;
}

sub get_from_dom($self) {
    return $self->header_from if $self->header_from;

    my $header = $self->header_from_raw or do {
        $self->result->reason( type => 'other', comment => "no header_from" );
        return;
    };

    # RFC 8616 §6: convert U-labels to A-labels before DNS lookups
    my @domains = grep { $self->is_valid_domain($_) }
        map { $self->to_ascii_domain($_) } _mailbox_domains($header);

    if ( !@domains ) {
        $self->result->reason(
            type    => 'other',
            comment => "invalid header_from: ($header)"
        );
        return;
    }

    # RFC 9989 A.3: the Sender header is forgeable, so never substitute it
    if ( @domains > 1 ) {
        $self->{_author_domains} = \@domains;
        return;
    }
    return $self->header_from( $domains[0] );
}

# RFC 5322 3.4: a mailbox's domain is in its addr-spec, never in a display
# name or comment, where list rewrites put the original author
sub _mailbox_domains($header) {
    ( my $mailboxes = $header ) =~ s/^\s*from\s*:\s*//i;
    $mailboxes = _strip_comments_and_quotes($mailboxes);

    my %domains;
    foreach my $mailbox ( split /,/, $mailboxes ) {
        my ($addr) = $mailbox =~ /<([^>]*)>/;
        $addr //= $mailbox;
        my ($dom) = $addr =~ /\@\s*([^\s@<>;,]+)\s*$/ or next;
        $dom = lc $dom;
        $dom =~ s/\.$//;
        $domains{$dom} = 1;
    }
    return sort keys %domains;
}

# RFC 5322 3.2: one pass, since a quote in a comment and a parenthesis in a
# quoted string are literal, and a quoted-pair escapes either delimiter
sub _strip_comments_and_quotes($text) {
    my ( $kept, $comment_depth, $in_quote ) = ( '', 0, 0 );
    while ( $text =~ /\G(\\.|.)/gs ) {
        my $char = $1;
        if ($in_quote) {
            $in_quote = 0 if $char eq '"';
        }
        elsif ($comment_depth) {
            $comment_depth++ if $char eq '(';
            $comment_depth-- if $char eq ')';
        }
        elsif ( $char eq '"' ) { $in_quote = 1 }
        elsif ( $char eq '(' ) { $comment_depth = 1 }
        else                   { $kept .= $char }
    }

    # unbalanced, so evaluate every address-like domain rather than lose one
    return $text if $in_quote || $comment_depth;
    return $kept;
}

sub external_report( $self, $uri ) {
    my $dmarc_dom = $self->result->published->domain
        or croak "published policy not tagged!";

    if ( 'mailto' eq $uri->scheme ) {
        my $dest_email = lc $uri->path;
        my ($dest_host) = ( split /@/, $dest_email )[-1];
        if ( $self->get_organizational_domain($dest_host) eq
            $self->get_organizational_domain($dmarc_dom) )
        {
            print "$dest_host not external for $dmarc_dom\n" if $self->verbose;
            return 0;
        }
        print "$dest_host is external for $dmarc_dom\n" if $self->verbose;
        return 1;
    }

    if ( $uri->scheme =~ /^https?$/ ) {
        if ( $uri->host eq $dmarc_dom ) {
            print $uri->host . " not external for $dmarc_dom\n" if $self->verbose;
            return 0;
        }
        print $uri->host . " is external for $dmarc_dom\n" if $self->verbose;
        return 1;
    }

    return 1;
}

sub _uri_authority_host($uri) {
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

sub verify_external_reporting( $self, $uri_ref = undef ) {
    $uri_ref or croak "missing URI";

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

    #  4.  If the length of the constructed name exceeds DNS limits, stop.
    if ( length $dest > 253 ) {
        print "\t$dest exceeds DNS name limits\n" if $self->verbose;
        return;
    }

    #  5.  Query the DNS for a TXT record at the constructed name.
    my $query = $self->get_resolver->send( $dest, 'TXT' ) or do {
        print "\tquery for $dest failed\n" if $self->verbose;
        return;
    };

    #  6.  For each record, parse the result...same overall format:
    #      "v=DMARC1" tag is mandatory and MUST appear first in the list.
    my @matches;
    for my $rr ( $query->answer ) {
        next if $rr->type ne 'TXT';
        my $txt = join '', $rr->txtdata;
        push @matches, $self->policy->parse($txt) if _is_dmarc_record($txt);
    }

    #  7.  If the result includes no TXT resource records...stop
    if ( !@matches ) {
        print "\tno TXT match for $dest\n" if $self->verbose;
        return;
    }

    #  8.  If a TXT resource record remains, external reporting is authorized
    #  9.  If a "rua" or "ruf" tag is discovered, replace the
    #      corresponding value with the one found in this record.
    my @overrides = grep { ref $_ && $_->{rua} } @matches;
    foreach my $or (@overrides) {
        my $recips_ref = $self->report->uri->parse( $or->{rua} ) or next;

        # an override to another host voids both destinations
        if ( grep { lc( _uri_authority_host( $_->{uri} ) // '' ) ne lc $dest_host }
            @$recips_ref )
        {
            print "\toverride RUA $or->{rua} leaves $dest_host\n" if $self->verbose;
            return;
        }
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

version 2.20260827

=head1 METHODS

=head2 init

Reset the Mail::DMARC object, preparing it for a fresh request.

=head2 validate

This method does the following:

=over 4

* query DNS for a DMARC policy (discover_policy); a DNS failure yields I<temperror>

* when the RFC5322.From header holds several domains, validate each one (up to 5) and keep the strictest result

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

=head1 NOT IMPLEMENTED

=head2 RFC 9991 - DMARC Failure Reporting

RFC 9991 defines the format and delivery of per-message DMARC failure reports
(forensic reports, sent via the C<ruf> tag). This module does B<not> implement
RFC 9991. Sending failure reports is not supported. The C<ruf> tag in a DMARC
policy record is parsed and stored but no failure reports are generated or
delivered.

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
