package Mail::DMARC::Report::URI;
# VERSION
use strict;
use warnings;

use Carp;
use URI;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub parse {
    my $self = shift;
    my $str = shift or croak "URI string is required!";

    my @valids = ();
    foreach my $raw ( split /,/, $str ) {
#       warn "raw: $raw\n" if $self->verbose;
        my ( $u, $size_f ) = split /!/, $raw;
        my $bytes = $self->get_size_limit($size_f);
        my $uri = URI->new($u) or do {
            carp "can't parse URI from $u";
            next;
        };
        my $scheme = $uri->scheme;
        if ( $scheme eq 'mailto' && lc substr( $u, 0, 7 ) eq 'mailto:' ) {
            push @valids, { max_bytes => $bytes, uri => $uri };
            next;
        }
        if ( $scheme =~ /^http(s)?/x && lc substr( $u, 0, 4 ) eq 'http' ) {
            push @valids, { max_bytes => $bytes, uri => $uri };
            next;
        }

#       print "invalid URI scheme: $scheme in $u\n";
 # 12.1 Discovery - URI schemes found in "rua" tag that are not implemented by
 #                  a Mail Receiver MUST be ignored.
    }
    return \@valids;
}

sub get_size_limit {
    my ( $self, $size ) = @_;
    return 0 if !defined $size;          # no limit
    return $size if $size =~ /^\d+$/;    # no units, raw byte count

# 6.3 Formal Definition
# units are considered to be powers of two; a kilobyte is 2^10, a megabyte is 2^20,
    my $unit = lc chop $size;
    return $size * ( 2**10 ) if 'k' eq $unit;
    return $size * ( 2**20 ) if 'm' eq $unit;
    return $size * ( 2**30 ) if 'g' eq $unit;
    return $size * ( 2**40 ) if 't' eq $unit;
    croak "unrecognized unit ($unit) in size ($size)";
}

1;

# ABSTRACT: a DMARC reporting URI
__END__
sub {}

=head1 ABNF

  dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]
            ; "URI" is imported from [URI]; commas (ASCII 0x2c)
            ; and exclamation points (ASCII 0x21) MUST be encoded

URI is imported from RFC 3986: https://www.ietf.org/rfc/rfc3986.txt

Only mailto, http, and https URIs are currently supported, examples:

    https://www.ietf.org/rfc/rfc3986.txt
    mailto:John.Doe@example.com

With an optional size limit (see SIZE LIMIT).

=head1 SIZE LIMIT

A size limitation in a dmarc-uri, if provided, is interpreted as a
count of units followed by an OPTIONAL unit size ("k" for kilobytes,
"m" for megabytes, "g" for gigabytes, "t" for terabytes).  Without a
unit, the number is presumed to be a basic byte count.  Note that the
units are considered to be powers of two; a kilobyte is 2^10, a
megabyte is 2^20, etc.

=head1 DESCRIPTION

defines a generic syntax for identifying a resource.  The DMARC
mechanism uses this as the format by which a Domain Owner specifies
the destination for the two report types that are supported.

The place such URIs are specified (see Section 6.2) allows a list of
these to be provided.  A report is to be sent to each listed URI.
Mail Receivers MAY impose a limit on the number of URIs that receive
reports, but MUST support at least two.  The list of URIs is
separated by commas (ASCII 0x2C).

Each URI can have associated with it a maximum report size that may
be sent to it.  This is accomplished by appending an exclamation
point (ASCII 0x21), followed by a maximum size indication, before a
separating comma or terminating semi-colon.

Thus, a DMARC URI is a URI within which any commas or exclamation
points are percent-encoded per [URI], followed by an OPTIONAL
exclamation point and a maximum size specification, and, if there are
additional reporting URIs in the list, a comma and the next URI.

For example, the URI "mailto:reports@example.com!50m" would request a
report be sent via email to "reports@example.com" so long as the
report payload does not exceed 50 megabytes.

A formal definition is provided in Section 6.3.

=cut
