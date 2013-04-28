package Mail::DMARC;
# ABSTRACT: Perl implementation of DMARC

use strict;
use warnings;

our $VERSION = 0.10;

=head1 NAME

Domain-based Message Authentication, Reporting and Conformance

=head1 SYNOPSIS

DMARC: a reliable means to authenticate who mail is from.

=head1 DESCRIPTION

From the DMARC Draft: "DMARC operates as a policy layer atop DKIM and SPF. These technologies are the building blocks of DMARC as each is widely deployed, supported by mature tools, and is readily available to both senders and receivers. They are complementary, as each is resilient to many of the failure modes of the other."

DMARC provides a way to exchange authentication information and policies among mail servers.

DMARC benefits domain owners by preventing others from impersonating them. A domain owner can reliably tell other mail servers that "it it doesn't originate from this list of servers (SPF) and it is not signed (DKIM), then reject it!" DMARC also provides domain owners with a means to receive feedback and determine that their policies are working as desired.

DMARC benefits mail server operators by providing them with an extremely reliable (as opposed to DKIM or SPF, which both have reliability issues when used independently) means to block forged emails. Is that message really from PayPal, Chase, Gmail, or Facebook? Since those organizations, and many more, publish DMARC policies, operators have a definitive means to know.

=head1 HOWTO

=head2 Protect a domain with DMARC

See Section 10 of the draft: Domain Owner Actions

 1. Deploy DKIM & SPF
 2. Ensure identifier alignment.
 3. Publish a "monitor" record, ask for data reports
 4. Roll policies from monitor to reject

=head3 Publish a DMARC policy

_dmarc  IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@example.com;"

 v=DMARC1;    (version)
 p=none;      (disposition policy : reject, quarantine, none (monitor))
 sp=reject;   (subdomain policy: default, same as p)
 adkim=s;     (dkim alignment: s=strict, r=relaxed)
 aspf=r;      (spf  alignment: s=strict, r=relaxed)
 rua=mailto: dmarc-feedback@example.com; (aggregate reports)
 ruf=mailto: dmarc-feedback@example.com; (forensic reports)
 rf=afrf;     (report format: afrf, iodef)
 ri=8400;     (report interval)
 pct=50;      (percent of messages to filter)

=head2 Validate messages with DMARC

1. install Mail::DMARC

2. install a public suffix. See http://publicsuffix.org/list/

3. install a SA rule?

=head2 Parse dmarc feedback reports into a database

See http://www.taugh.com/rddmarc/

=head1 MORE INFORMATION

http://www.dmarc.org/draft-dmarc-base-00-02.txt

https://github.com/qpsmtpd-dev/qpsmtpd-dev/wiki/DMARC-FAQ

=head1 TODO

 2. provide dmarc feedback to domains that request it

=head1 AUTHORS

 2013 - Matt Simerson <msimerson@cpan.org>

=cut


1;
