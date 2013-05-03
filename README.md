# mail-dmarc
==========

# DMARC: Domain-based Message Authentication, Reporting and Conformance

[Mail::DMARC](lib/Mail/DMARC.pm) - A perl implementation of the DMARC draft

[Mail::DMARC::Policy](lib/Mail/DMARC/Policy.pm) - a DMARC record in object format

[Mail::DMARC::PurePerl](lib/Mail/DMARC/PurePerl.pm) - a DMARC implementation

* [Mail::DMARC::Report](lib/Mail/DMARC/Report.pm)
* [Mail::DMARC::Report::AFRF](lib/Mail/DMARC/Report/AFRF.pm)
* [Mail::DMARC::Report::IODEF](lib/Mail/DMARC/Report/IODEF.pm)

[Mail::DMARC::URI](lib/Mail/DMARC/URI.pm) - a DMARC reporting URI

[Mail::DMARC::libopendmarc](http://search.cpan.org/~shari/Mail-DMARC-opendmarc) - an XS implementation using libopendmarc


## What is DMARC?

DMARC provides a way to exchange authentication information and policies among mail servers.

DMARC benefits domain owners by preventing others from impersonating them. A domain owner can reliably tell other mail servers that "it it doesn't originate from this list of servers (SPF) and it is not signed (DKIM), then reject it!" DMARC also provides domain owners with a means to receive feedback and determine that their policies are working as desired.

DMARC benefits mail server operators by providing them with an extremely reliable (as opposed to DKIM or SPF, which both have reliability issues when used independently) means to block forged emails. Is that message really from PayPal, Chase, Gmail, or Facebook? Since those organizations, and many more, publish DMARC policies, operators have a definitive means to know.

## How does DMARC work?

From the DMARC Draft: "DMARC operates as a policy layer atop DKIM and SPF. These technologies are the building blocks of DMARC as each is widely deployed, supported by mature tools, and is readily available to both senders and receivers. They are complementary, as each is resilient to many of the failure modes of the other."

## Protect a domain with DMARC

For details on these steps, see Section 10 of the draft: Domain Owner Actions

    1. Deploy DKIM & SPF
    2. Ensure identifier alignment.
    3. Publish a "monitor" record, ask for data reports
    4. Roll policies from monitor to reject


## How do I validate messages with DMARC?

    1. install Mail::DMARC

    2. install a public suffix. See http://publicsuffix.org/list/

    3. process messages through DMARC

        a. With the [Qpsmtpd DMARC plugin](https://github.com/qpsmtpd-dev/qpsmtpd-dev/blob/master/plugins/dmarc)
        b. With a SpamAssassin rule?
        c. other ideas here...

## Where can I find more information on DMARC?

http://www.dmarc.org/

http://dmarcian.com

Mar 31, 2013 Draft: https://datatracker.ietf.org/doc/draft-kucherawy-dmarc-base/

Mar 30, 2012 Draft: http://www.dmarc.org/draft-dmarc-base-00-02.txt

https://github.com/qpsmtpd-dev/qpsmtpd-dev/wiki/DMARC-FAQ

