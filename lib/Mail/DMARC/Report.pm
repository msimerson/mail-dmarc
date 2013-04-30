package Mail::DMARC::Report;
# ABSTRACT: A DMARC report object
use strict;
use warnings;

=head1 SYNOPSIS

REPORT URIs

=head1 REPORTING

The report SHOULD include the following data:

   o  Enough information for the report consumer to re-calculate DMARC
      disposition based on the published policy, message dispositon, and
      SPF, DKIM, and identifier alignment results. {R12}

   o  Data for each sender subdomain separately from mail from the
      sender's organizational domain, even if no subdomain policy is
      applied. {R13}

   o  Sending and receiving domains {R17}

   o  The policy requested by the Domain Owner and the policy actually
      applied (if different) {R18}

   o  The number of successful authentications {R19}

   o  The counts of messages based on all messages received even if
      their delivery is ultimately blocked by other filtering agents {R20}

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

=cut


1;
