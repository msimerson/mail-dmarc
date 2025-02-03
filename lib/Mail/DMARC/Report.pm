package Mail::DMARC::Report;
use strict;
use warnings;

our $VERSION = '1.20250203';

use Carp;
use IO::Compress::Gzip;
use IO::Compress::Zip;

use parent 'Mail::DMARC::Base';

require Mail::DMARC::Report::Aggregate;
require Mail::DMARC::Report::Send;
require Mail::DMARC::Report::Store;
require Mail::DMARC::Report::Receive;
require Mail::DMARC::Report::URI;

sub compress {
    my ( $self, $xml_ref ) = @_;
    croak "xml is not a reference!" if 'SCALAR' ne ref $xml_ref;
    my $shrunk;
    my $zipper = {
        gz  => \&IO::Compress::Gzip::gzip,    # 2013 draft
        zip => \&IO::Compress::Zip::zip,      # legacy format
    };
# WARNING: changes here MAY require updates in SMTP::assemble_message
#   my $cf = ( time > 1372662000 ) ? 'gz' : 'zip';    # gz after 7/1/13
    my $cf = 'gz';
    $zipper->{$cf}->( $xml_ref, \$shrunk ) or croak "unable to compress: $!";
    return $shrunk;
}

sub init {
    my $self = shift;
    delete $self->{dmarc};
    delete $self->{aggregate};
    return;
}

sub aggregate {
    my $self = shift;
    return $self->{aggregate} if ref $self->{aggregate};
    return $self->{aggregate} = Mail::DMARC::Report::Aggregate->new();
}

sub dmarc {
    my $self = shift;
    return $self->{dmarc};
}

sub receive {
    my $self = shift;
    return $self->{receive} if ref $self->{receive};
    return $self->{receive} = Mail::DMARC::Report::Receive->new;
}

sub sendit {
    my $self = shift;
    return $self->{sendit} if ref $self->{sendit};
    return $self->{sendit} = Mail::DMARC::Report::Send->new();
}

sub store {
    my $self = shift;
    return $self->{store} if ref $self->{store};
    return $self->{store} = Mail::DMARC::Report::Store->new();
}

sub uri {
    my $self = shift;
    return $self->{uri} if ref $self->{uri};
    return $self->{uri} = Mail::DMARC::Report::URI->new();
}

sub save_aggregate {
    my $self = shift;
    return $self->store->backend->save_aggregate( $self->aggregate );
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report - A DMARC report interface

=head1 VERSION

version 1.20250203

=head1 DESCRIPTION

DMARC reports are information that a DMARC implementing Mail Transfer Agent (MTA) sends to Author Domains and also something that an Author Domain owner receives from other DMARC implementing MTAs. Mail::DMARC supports both roles, as a sender and a receiver.

There are two report types, L<aggregate|Mail::DMARC::Report::Aggregate> and forensic.

=head1 Aggregate Reports

See L<Mail::DMARC::Report::Aggregate>

=head2 Forensic Reports

TODO

=head2 Report Sender

See L<Mail::DMARC::Report::Send>

    1. store reports
    2. bundle aggregated reports
    3. format report in XML
    4. gzip the XML
    5. deliver report to Author Domain

=head2 Report Receiver

See L<Mail::DMARC::Report::Receive>

    1. accept reports via HTTP or SMTP
    2. parse the compressed XML message
    3. store the report
    4. present stored data

=head2 Verify External Destinations

  1.  Extract the host portion of the authority component of the URI.
       Call this the "destination host".

   2.  Prepend the string "_report._dmarc".

   3.  Prepend the domain name from which the policy was retrieved.

   4.  Query the DNS for a TXT record at the constructed name.  If the
       result of this request is a temporary DNS error of some kind
       (e.g., a timeout), the Mail Receiver MAY elect to temporarily
       fail the delivery so the verification test can be repeated later.

   5.  If the result includes no TXT resource records or multiple TXT
       resource records, a positive determination of the external
       reporting relationship cannot be made; stop.

   6.  Parse the result, if any, as a series of "tag=value" pairs, i.e.,
       the same overall format as the policy record.  In particular, the
       "v=DMARC1" tag is mandatory and MUST appear first in the list.
       If at least that tag is present and the record overall is
       syntactically valid per Section 6.3, then the external reporting
       arrangement was authorized by the destination ADMD.

   7.  If a "rua" or "ruf" tag is thus discovered, replace the
       corresponding value extracted from the domain's DMARC policy
       record with the one found in this record.  This permits the
       report receiver to override the report destination.  However, to
       prevent loops or indirect abuse, the overriding URI MUST use the
       same destination host from the first step.

=head1 ERROR REPORTS

12.2.4.  Error Reports

When a Mail Receiver is unable to complete delivery of a report via
any of the URIs listed by the Domain Owner, the Mail Receiver SHOULD
generate an error message.  An attempt MUST be made to send this
report to all listed "mailto" URIs and MAY also be sent to any or all
other listed URIs.

The error report MUST be formatted per [MIME].  A text/plain part
MUST be included that contains field-value pairs such as those found
in Section 2 of [DSN].  The fields required, which may appear in any
order, are:

Report-Date:  A [MAIL]-formatted date expression indicating when the transport failure occurred.

Report-Domain:  The domain-name about which the failed report was generated.

Report-ID:  The Report-ID: that the report tried to use.

Report-Size:  The size, in bytes, of the report that was unable to be
    sent.  This MUST represent the number of bytes that the Mail
    Receiver attempted to send.  Where more than one transport system
    was attempted, the sizes may be different; in such cases, separate
    error reports MUST be generated so that this value matches the
    actual attempt that was made.  For example, a "mailto" error
    report would be sent to the "mailto" URIs with one size, while the
    "https" reports might be POSTed to those URIs with a different
    size, as they have different transport and encoding requirements.

Submitter:  The domain-name representing the Mail Receiver that generated, but was unable to submit, the report.

Submitting-URI:  The URI(s) to which the Mail Receiver tried, but failed, to submit the report.

An additional text/plain part MAY be included that gives a human-
readable explanation of the above, and MAY also include a URI that
can be used to seek assistance.

[NOTE: A more rigorous syntax specification, including ABNF and
possible registration of a new media type, will be added here when
more operational experience is acquired.]

=head1 AFRF reports

=head1 IODEF reports

https://datatracker.ietf.org/doc/draft-kucherawy-dmarc-base/?include_text=1

Section 3.5 Out of Scope:

    This first version of DMARC supports only a single reporting format.

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

This software is copyright (c) 2024 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

