package Mail::DMARC::Policy;
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)

our $VERSION = '2.20260621';

use Carp;

use Mail::DMARC::Report::URI;

sub new( $class, @args ) {
    my $package = ref $class ? ref $class : $class;
    my $self    = bless {}, $package;

    return $self if !@args;    # no args, empty pol
    if ( 1 == @args ) {        # a string
        my $policy = $self->parse( $args[0] );
        $self->is_valid($policy);
        return $policy;
    }

    croak "invalid arguments" if @args % 2 != 0;
    my $policy = {@args};
    bless $policy, $package;
    croak "invalid  policy" if !$self->is_valid($policy);
    return bless $policy, $package;
}

sub parse( $self, $str, @junk ) {
    croak "invalid parse request" if @junk;
    my $cleaned = $str;
    $cleaned =~ s/\s//g;                               # remove whitespace
    $cleaned =~ s/\\;/;/g;                             # replace \;  with ;
    $cleaned =~ s/;;/;/g;                              # replace ;;  with ;
    $cleaned =~ s/;0;/;/g;                             # replace ;0; with ;
    chop $cleaned if ';' eq substr $cleaned, -1, 1;    # remove a trailing ;
    my @tag_vals = split /;/, $cleaned;
    my %policy;
    my $warned = 0;

    foreach my $tv (@tag_vals) {
        my ( $tag, $value ) = split /=|:|-/, $tv, 2;
        if ( !defined $tag || !defined $value || $value eq '' ) {
            if ( !$warned ) {

                #warn "tv: $tv\n";
                warn "invalid DMARC record, please post this message to\n"
                    . "\thttps://github.com/msimerson/mail-dmarc/issues/39\n"
                    . "\t$str\n";
            }
            $warned++;
            next;
        }
        $policy{ lc $tag } = $value;
    }

    # RFC 9989: an unrecognized value for an optional tag is ignored (the tag
    # reverts to its default); it MUST NOT invalidate the whole record. The
    # setters croak, so normalize here on the parse-from-DNS path instead.
    if ( defined $policy{psd} && $policy{psd} !~ /^[ynu]$/i ) {
        warn "ignoring invalid psd ($policy{psd})\n";
        delete $policy{psd};
    }
    if ( defined $policy{t} && $policy{t} !~ /^[yn]$/i ) {
        warn "ignoring invalid t ($policy{t})\n";
        delete $policy{t};
    }

    return bless \%policy, ref $self;    # inherited defaults + overrides
}

sub stringify($self) {
    my %dmarc_record = %{$self};
    delete $dmarc_record{domain};

    my $dmarc_txt = 'v=' . ( delete $dmarc_record{v} );    # "v" tag must be first
    foreach my $key ( keys %dmarc_record ) {
        $dmarc_txt .= "; $key=$dmarc_record{$key}";
    }
    return $dmarc_txt;
}

sub apply_defaults($self) {
    $self->adkim('r') if !defined $self->adkim;
    $self->aspf('r')  if !defined $self->aspf;
    $self->fo(0)      if !defined $self->fo;

    # rf, ri, pct are deprecated in DMARCbis (RFC 9989) and MUST be ignored
    return 1;
}

sub v( $self, $val = undef ) {
    return $self->{v}                 if @_ == 1;
    croak "unsupported DMARC version" if 'DMARC1' ne uc $val;
    return $self->{v} = $val;
}

sub p( $self, $val = undef ) {
    return $self->{p} if @_ == 1;
    croak "invalid p" if !$self->is_valid_p($val);
    return $self->{p} = $val;
}

sub sp( $self, $val = undef ) {
    return $self->{sp}        if @_ == 1;
    croak "invalid sp ($val)" if !$self->is_valid_p($val);
    return $self->{sp} = $val;
}

sub np( $self, $val = undef ) {
    return $self->{np}        if @_ == 1;
    croak "invalid np ($val)" if !$self->is_valid_p($val);
    return $self->{np} = $val;
}

sub psd( $self, $val = undef ) {
    return $self->{psd}        if @_ == 1;
    croak "invalid psd ($val)" if 0 == grep {/^\Q$val\E$/i} qw/ y n u /;
    return $self->{psd} = lc $val;
}

sub t( $self, $val = undef ) {
    return $self->{t}        if @_ == 1;
    croak "invalid t ($val)" if 0 == grep {/^\Q$val\E$/i} qw/ y n /;
    return $self->{t} = lc $val;
}

sub adkim( $self, $val = undef ) {
    return $self->{adkim} if @_ == 1;
    croak "invalid adkim" if 0 == grep {/^\Q$val\E$/ix} qw/ r s /;
    return $self->{adkim} = $val;
}

sub aspf( $self, $val = undef ) {
    return $self->{aspf} if @_ == 1;
    croak "invalid aspf" if 0 == grep {/^\Q$val\E$/ix} qw/ r s /;
    return $self->{aspf} = $val;
}

sub fo( $self, $val = undef ) {
    return $self->{fo}       if @_ == 1;
    croak "invalid fo: $val" if $val !~ /^[01ds](:[01ds])*$/ix;
    return $self->{fo} = $val;
}

sub rua( $self, $val = undef ) {
    return $self->{rua} if @_ == 1;
    croak "invalid rua" if !$self->is_valid_uri_list($val);
    return $self->{rua} = $val;
}

sub ruf( $self, $val = undef ) {
    return $self->{ruf} if @_ == 1;
    croak "invalid rua" if !$self->is_valid_uri_list($val);
    return $self->{ruf} = $val;
}

sub rf( $self, $val = undef ) {
    return $self->{rf} if @_ == 1;
    foreach my $f ( split /,/, $val ) {
        croak "invalid format: $f" if !$self->is_valid_rf($f);
    }
    return $self->{rf} = $val;
}

sub ri( $self, $val = undef ) {
    return $self->{ri}          if @_ == 1;
    croak "not numeric ($val)!" if $val =~ /\D/;
    croak "not an integer!"     if $val != int $val;
    croak "out of range"        if ( $val < 0 || $val > 4294967295 );
    return $self->{ri} = $val;
}

sub pct( $self, $val = undef ) {
    return $self->{pct}         if @_ == 1;
    croak "not numeric ($val)!" if $val =~ /\D/;
    croak "not an integer!"     if $val != int $val;
    croak "out of range"        if $val < 0 || $val > 100;
    return $self->{pct} = $val;
}

sub domain( $self, $val = undef ) {
    return $self->{domain} if @_ == 1;
    return $self->{domain} = $val;
}

sub is_valid_rf( $self, $f ) {
    return ( grep {/^\Q$f\E$/i} qw/ iodef afrf / ) ? 1 : 0;
}

sub is_valid_p( $self, $p ) {
    croak "unspecified p" if !defined $p;
    return ( grep {/^\Q$p\E$/i} qw/ none reject quarantine / ) ? 1 : 0;
}

sub is_valid_uri_list( $self, $str ) {
    $self->{uri} ||= Mail::DMARC::Report::URI->new;
    my $uris = $self->{uri}->parse($str);
    return scalar @$uris;
}

sub is_valid( $self, $obj = undef ) {
    $obj = $self                      if !$obj;
    croak "missing version specifier" if !$obj->{v};
    croak "invalid version"           if 'DMARC1' ne uc $obj->{v};

    # psd=y domains (PSDs) are not required to have a p= tag
    my $is_psd = defined $obj->{psd} && lc $obj->{psd} eq 'y';

    if ( !$obj->{p} && !$is_psd ) {
        if ( $obj->{rua} && $self->is_valid_uri_list( $obj->{rua} ) ) {
            $obj->{p} = 'none';
        }
        else {
            croak "missing policy action (p=)";
        }
    }
    if ( $obj->{p} ) {
        croak "invalid policy action" if !$self->is_valid_p( $obj->{p} );
    }
    if ( defined $obj->{np} ) {
        croak "invalid np" if !$self->is_valid_p( $obj->{np} );
    }

    # everything else is optional
    return 1;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Policy - a DMARC policy in object format

=head1 VERSION

version 2.20260621

=head1 SYNOPSIS

 my $pol = Mail::DMARC::Policy->new(
    'v=DMARC1; p=none; rua=mailto:dmarc@example.com'
    );

 print "not a valid DMARC version!"    if $pol->v ne 'DMARC1';
 print "take no action"                if $pol->p eq 'none';
 print "reject that unaligned message" if $pol->p eq 'reject';
 print "do not send aggregate reports" if ! $pol->rua;
 print "do not send forensic reports"  if ! $pol->ruf;

=head1 EXAMPLES

A DMARC record in DNS format looks like this:

    v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@example.com;

DMARC records are stored in TXT resource records in the DNS, at _dmarc.example.com. To retrieve a DMARC record for a domain:

=head2 dig

    dig +short _dmarc.example.com TXT

=head2 perlishly

    print $_->txtdata."\n"
      for Net::DNS::Resolver->new(dnsrch=>0)->send('_dmarc.example.com','TXT')->answer;

=head2 dmarc_lookup

    dmarc_lookup example.com

=head1 METHODS

All methods validate their input against the DMARC specification (RFC 7489 / DMARCbis RFC 9989). Attempts to set invalid values will throw exceptions.

=head2 new

Create a new empty policy:

 my $pol = Mail::DMARC::Policy->new;

Create a new policy from named arguments:

 my $pol = Mail::DMARC::Policy->new(
         v => 'DMARC1',
         p => 'none',
         );

Create a new policy from a DMARC DNS resource record:

 my $pol = Mail::DMARC::Policy->new(
         'v=DMARC1; p=reject; rua=mailto:dmarc@example.com;'
         );

If a policy is passed in (the latter two examples), the resulting policy object will be an exact representation of the record as returned from DNS.

=head2 apply_defaults

The DMARC tags C<adkim>, C<aspf>, and C<fo> have default values when not specified in the published DNS record. Calling I<apply_defaults> will apply those defaults to tags not present in the DNS record.

C<rf>, C<ri>, and C<pct> are deprecated in DMARCbis (RFC 9989) and MUST be ignored; C<apply_defaults> no longer sets them.

=head2 parse

Accepts a string containing a DMARC Resource Record, as it would be retrieved
via DNS.

    my $pol = Mail::DMARC::Policy->new;
    $pol->parse( 'v=DMARC1; p=none; rua=mailto:dmarc@example.com' );
    $pol->parse( 'v=DMARC1' );       # external reporting record

=head2 stringify

Returns the textual representation of the DMARC record.

    my $pol = Mail::DMARC::Policy->new('v=DMARC1; p=none;');
    print $pol->stringify;

=head1 Record Tags

=head2 Tag Overview

 v=DMARC1;    (version)
 p=none;      (disposition policy : reject, quarantine, none (monitor))
 sp=reject;   (subdomain policy: same as p)
 adkim=s;     (dkim alignment: s=strict, r=relaxed)
 aspf=r;      (spf  alignment: s=strict, r=relaxed)
 rua=mailto:dmarc-feedback@example.com; (aggregate reports)
 ruf=mailto:dmarc-feedback@example.com; (forensic reports)
 rf=afrf;     (DEPRECATED in DMARCbis: report format)
 ri=8400;     (DEPRECATED in DMARCbis: report interval)
 pct=50;      (DEPRECATED in DMARCbis: percent of messages to filter)

=head2 Tags in Detail

The descriptions of each DMARC record tag and its corresponding values is from the March 31, 2013 draft of the DMARC spec:

https://datatracker.ietf.org/doc/draft-kucherawy-dmarc-base/?include_text=1

Each tag has a mutator that's a setter and getter. To set any of the tag values, pass in the new value. Examples:

  $pol->p('none');                         set policy action to none
  print "do nothing" if $pol->p eq 'none'; get policy action

=head2 v

Version (plain-text; REQUIRED).  Identifies the record retrieved
as a DMARC record.  It MUST have the value of "DMARC1".  The value
of this tag MUST match precisely; if it does not or it is absent,
the entire retrieved record MUST be ignored.  It MUST be the first
tag in the list.

=head2 p

Requested Mail Receiver policy (plain-text; REQUIRED for policy
records).  Indicates the policy to be enacted by the Receiver at
the request of the Domain Owner.  Policy applies to the domain
queried and to sub-domains unless sub-domain policy is explicitly
described using the "sp" tag.  This tag is mandatory for policy
records only, but not for third-party reporting records (see
Section 8.2).

=head2 sp

{R6} Requested Mail Receiver policy for subdomains (plain-text;
OPTIONAL).  Indicates the policy to be enacted by the Receiver at
the request of the Domain Owner.  It applies only to subdomains of
the domain queried and not to the domain itself.  Its syntax is
identical to that of the "p" tag defined above.  If absent, the
policy specified by the "p" tag MUST be applied for subdomains.

=head2 adkim

(plain-text; OPTIONAL, default is "r".)  Indicates whether or
not strict DKIM identifier alignment is required by the Domain
Owner.  If and only if the value of the string is "s", strict mode
is in use.  See Section 4.3.1 for details.

=head2 aspf

(plain-text; OPTIONAL, default is "r".)  Indicates whether or
not strict SPF identifier alignment is required by the Domain
Owner.  If and only if the value of the string is "s", strict mode
is in use.  See Section 4.3.2 for details.

=head2 fo

Failure reporting options (plain-text; OPTIONAL, default "0"))
Provides requested options for generation of failure reports.
Report generators MAY choose to adhere to the requested options.
This tag's content MUST be ignored if a "ruf" tag (below) is not
also specified.  The value of this tag is a colon-separated list
of characters that indicate failure reporting options as follows:

  0: Generate a DMARC failure report if all underlying
     authentication mechanisms failed to produce an aligned "pass"
     result.

  1: Generate a DMARC failure report if any underlying
     authentication mechanism failed to produce an aligned "pass"
     result.

  d: Generate a DKIM failure report if the message had a signature
     that failed evaluation, regardless of its alignment.  DKIM-
     specific reporting is described in [AFRF-DKIM].

  s: Generate an SPF failure report if the message failed SPF
     evaluation, regardless of its alignment. SPF-specific
     reporting is described in [AFRF-SPF].

=head2 rua

Addresses to which aggregate feedback is to be sent (comma-
separated plain-text list of DMARC URIs; OPTIONAL). {R11} A comma
or exclamation point that is part of such a DMARC URI MUST be
encoded per Section 2.1 of [URI] so as to distinguish it from the
list delimiter or an OPTIONAL size limit.  Section 8.2 discusses
considerations that apply when the domain name of a URI differs
from that of the domain advertising the policy.  See Section 15.6
for additional considerations.  Any valid URI can be specified.  A
Mail Receiver MUST implement support for a "mailto:" URI, i.e. the
ability to send a DMARC report via electronic mail.  If not
provided, Mail Receivers MUST NOT generate aggregate feedback
reports.  URIs not supported by Mail Receivers MUST be ignored.
The aggregate feedback report format is described in Section 8.3.

=head2 ruf

Addresses to which message-specific failure information is to
be reported (comma-separated plain-text list of DMARC URIs;
OPTIONAL). {R11} If present, the Domain Owner is requesting Mail
Receivers to send detailed failure reports about messages that
fail the DMARC evaluation in specific ways (see the "fo" tag
above).  The format of the message to be generated MUST follow
that specified in the "rf" tag.  Section 8.2 discusses
considerations that apply when the domain name of a URI differs
from that of the domain advertising the policy.  A Mail Receiver
MUST implement support for a "mailto:" URI, i.e. the ability to
send a DMARC report via electronic mail.  If not provided, Mail
Receivers MUST NOT generate failure reports.  See Section 15.6 for
additional considerations.

=head2 rf

B<Deprecated in DMARCbis (RFC 9989).> This tag MUST be ignored; it is documented here for historical reference only.

Format to be used for message-specific failure reports (comma-
separated plain-text list of values; OPTIONAL; default "afrf").
The value of this tag is a list of one or more report formats as
requested by the Domain Owner to be used when a message fails both
[SPF] and [DKIM] tests to report details of the individual
failure.  The values MUST be present in the registry of reporting
formats defined in Section 14; a Mail Receiver observing a
different value SHOULD ignore it, or MAY ignore the entire DMARC
record.  Initial default values are "afrf" (defined in [AFRF]) and
"iodef" (defined in [IODEF]).  See Section 8.4 for details.

=head2 ri

B<Deprecated in DMARCbis (RFC 9989).> This tag MUST be ignored; it is documented here for historical reference only.

Interval requested between aggregate reports (plain-text, 32-bit
unsigned integer; OPTIONAL; default 86400). {R14} Indicates a
request to Receivers to generate aggregate reports separated by no
more than the requested number of seconds.  DMARC implementations
MUST be able to provide daily reports and SHOULD be able to
provide hourly reports when requested.  However, anything other
than a daily report is understood to be accommodated on a best-
effort basis.

=head2 pct

B<Deprecated in DMARCbis (RFC 9989).> This tag MUST be ignored; it is documented here for historical reference only.

(plain-text integer between 0 and 100, inclusive; OPTIONAL;
default is 100). {R8} Percentage of messages from the DNS domain's
mail stream to which the DMARC mechanism is to be applied.
However, this MUST NOT be applied to the DMARC-generated reports,
all of which must be sent and received unhindered.  The purpose of
the "pct" tag is to allow Domain Owners to enact a slow rollout
enforcement of the DMARC mechanism.  The prospect of "all or
nothing" is recognized as preventing many organizations from
experimenting with strong authentication-based mechanisms.  See
Section 7.1 for details.

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
