package Mail::DMARC::URI;
# ABSTRACT: a DMARC reporting URI
use strict;
use warnings;


1;

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

