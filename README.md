# NAME

Mail::DMARC - Perl implementation of DMARC

# VERSION

version 1.20150817

# SYNOPSIS

DMARC: Domain-based Message Authentication, Reporting and Conformance

     my $dmarc = Mail::DMARC::PurePerl->new(
       ... # see the documentation for the "new" method for required args
     );

     my $result = $dmarc->validate();

    if ( $result->result eq 'pass' ) {
        ...continue normal processing...
        return;
    };

    # any result that did not pass is a fail. Now for disposition

    if ( $result->evalated->disposition eq 'reject' ) {
        ...treat the sender to a 550 ...
    };
    if ( $result->evalated->disposition eq 'quarantine' ) {
        ...assign a bunch of spam points...
    };
    if ( $result->evalated->disposition eq 'none' ) {
        ...continue normal processing...
    };

# DESCRIPTION

This module is a suite of tools for implementing DMARC. It adheres very tightly to the 2013 DMARC draft, intending to implement every MUST and every SHOULD.

This module can be used...

- by MTAs and filtering tools like SpamAssassin to validate that incoming messages are aligned with the purported sender's policy.
- by email senders, to receive DMARC reports from other mail servers and display them via CLI and web interfaces.
- by MTA operators to send DMARC reports to DMARC author domains.

When a message arrives via SMTP, the MTA or filtering application can pass in a small amount of metadata about the connection (envelope details, SPF and DKIM results) to Mail::DMARC. When the **validate** method is called, Mail::DMARC will determine if:

    a. the header_from domain exists
    b. the header_from domain publishes a DMARC policy
    c. if not, end processing
    d. does the message conform to the published policy?
    e. did the policy request reporting? If so, save details.

The validation results are returned as a [Mail::DMARC::Result](https://metacpan.org/pod/Mail::DMARC::Result) object. If the author domain requested a report, it was saved to the [Report Store](https://metacpan.org/pod/Mail::DMARC::Report::Store). The Store class includes a SQL implementation that is tested with SQLite and MySQL.

There is more information available in the $result object. See [Mail::DMARC::Result](https://metacpan.org/pod/Mail::DMARC::Result) for complete details.

Reports are viewed with the [dmarc\_view\_reports](https://metacpan.org/pod/dmarc_view_reports) program or with a web browser and the [dmarc\_httpd](https://metacpan.org/pod/dmarc_httpd) program.

Aggregate reports are sent to their requestors with the [dmarc\_send\_reports](https://metacpan.org/pod/dmarc_send_reports) program.

For aggregate reports that you have been sent, the [dmarc\_receive](https://metacpan.org/pod/dmarc_receive) program will parse the email messages (from IMAP, Mbox, or files) and save the report results into the [Report Store](https://metacpan.org/pod/Mail::DMARC::Report::Store).

The report store can use the same database to store reports you have received as well as reports you will send. There are several ways to identify the difference, including:

- received reports will have a null value for report\_policy\_published.rua
- outgoing reports will have null values for report.uuid and report\_record.count

# Code Climate

[![Build Status](https://travis-ci.org/msimerson/mail-dmarc.svg?branch=master)](https://travis-ci.org/msimerson/mail-dmarc)

[![Coverage Status](https://coveralls.io/repos/msimerson/mail-dmarc/badge.svg)](https://coveralls.io/r/msimerson/mail-dmarc)

[![Stories in Ready](https://badge.waffle.io/msimerson/mail-dmarc.png?label=ready&title=Ready)](https://waffle.io/msimerson/mail-dmarc)

# CLASSES

[Mail::DMARC](https://metacpan.org/pod/Mail::DMARC) - the perl interface for DMARC

[Mail::DMARC::Policy](https://metacpan.org/pod/Mail::DMARC::Policy) - a DMARC policy

[Mail::DMARC::PurePerl](https://metacpan.org/pod/Mail::DMARC::PurePerl) - Pure Perl implementation of DMARC

[Mail::DMARC::Result](https://metacpan.org/pod/Mail::DMARC::Result) - the results of applying policy

[Mail::DMARC::Report](https://metacpan.org/pod/Mail::DMARC::Report) - Reporting: the R in DMARC

> [Mail::DMARC::Report::Send](https://metacpan.org/pod/Mail::DMARC::Report::Send) - send reports via SMTP & HTTP
>
> [Mail::DMARC::Report::Receive](https://metacpan.org/pod/Mail::DMARC::Report::Receive) - receive and store reports from email, HTTP
>
> [Mail::DMARC::Report::Store](https://metacpan.org/pod/Mail::DMARC::Report::Store) - a persistent data store for aggregate reports
>
> [Mail::DMARC::Report::View](https://metacpan.org/pod/Mail::DMARC::Report::View) - CLI and CGI methods for viewing reports

[Mail::DMARC::libopendmarc](http://search.cpan.org/~shari/Mail-DMARC-opendmarc) - an XS implementation using libopendmarc

# METHODS

## new

Create a DMARC object.

    my $dmarc = Mail::DMARC::PurePerl->new;

Populate it.

    $dmarc->source_ip('192.0.1.1');
    $dmarc->envelope_to('recipient.example.com');
    $dmarc->envelope_from('sender.example.com');
    $dmarc->header_from('sender.example.com');
    $dmarc->dkim( $dkim_verifier );
    $dmarc->spf([
        {   domain => 'example.com',
            scope  => 'mfrom',
            result => 'pass',
        },
        {
            scope  => 'helo',
            domain => 'mta.example.com',
            result => 'fail',
        },
    ]);

Run the request:

    my $result = $dmarc->validate();

Alternatively, pass in all the required parameters in one shot:

    my $dmarc = Mail::DMARC::PurePerl->new(
            source_ip     => '192.0.1.1',
            envelope_to   => 'example.com',
            envelope_from => 'cars4you.info',
            header_from   => 'yahoo.com',
            dkim          => $dkim_results,  # same format
            spf           => $spf_results,   # as previous example
            );
    my $result = $dmarc->validate();

## source\_ip

The remote IP that attempted sending the message. DMARC only uses this data for reporting to domains that request DMARC reports.

## envelope\_to

The domain portion of the RFC5321.RcptTo, (aka, the envelope recipient), and the bold portion in the following example:

> RCPT TO:<user@**example.com**>

## envelope\_from

The domain portion of the RFC5321.MailFrom, (aka, the envelope sender). That is the the bold portion in the following example:

> MAIL FROM:<user@**example.com**>

## header\_from

The domain portion of the RFC5322.From, aka, the From message header.

> From: Ultimate Vacation <sweepstakes@**example.com**>

You can instead pass in the entire From: header with header\_from\_raw.

## header\_from\_raw

Retrieve the header\_from domain by parsing it from a raw From field/header. The domain portion is extracted by [get\_dom\_from\_header](https://metacpan.org/pod/Mail::DMARC::PurePerl#get_dom_from_header), which is fast, generally effective, but also rather crude. It has limits, so read the description.

## dkim

If Mail::DKIM::Verifier was used to validate the message, just pass in the Mail::DKIM::Verifier object that processed the message:

    $dmarc->dkim( $dkim_verifier );

Otherwise, pass in an array reference. Each member of the DKIM array results represents a DKIM signature in the message and consists of the 4 keys shown in this example:

    $dmarc->dkim( [
            {
                domain      => 'example.com',
                selector    => 'apr2013',
                result      => 'fail',
                human_result=> 'fail (body has been altered)',
            },
            {
                # 2nd signature, if present
            },
        ] );

The dkim results can also be build iteratively by passing in key value pairs or hash references for each signature in the message:

    $dmarc->dkim( domain => 'sig1.com', result => 'fail' );
    $dmarc->dkim( domain => 'sig2.com', result => 'pass' );
    $dmarc->dkim( { domain => 'example.com', result => 'neutral' } );

Each hash or hashref is appended to the dkim array.

Finally, you can pass a coderef which won't be called until the dkim method is used to read the dkim results.  It must return an array reference as described above.

The dkim result is an array reference.

### domain

The d= parameter in the DKIM signature

### selector

The s= parameter in the DKIM signature

### result

The validation results of this signature. One of: none, pass, fail, policy, neutral, temperror, or permerror

### human result

Additional information about the DKIM result. This is comparable to Mail::DKIM::Verifier->result\_detail.

## spf

The spf method works exactly the same as dkim. It accepts named arguments, a hashref, an arrayref, or a coderef:

    $dmarc->spf(
        domain => 'example.com',
        scope  => 'mfrom',
        result => 'pass',
    );

The SPF domain and result are required for DMARC validation and the scope is used for reporting.

### domain

The SPF checked domain

### scope

The scope of the checked domain: mfrom, helo

### result

The SPF result code: none, neutral, pass, fail, softfail, temperror, or permerror.

# DESIGN & GOALS

## Correct

The DMARC spec is lengthy and evolving, making correctness a moving target. In cases where correctness is ambiguous, options are generally provided.

## Easy to use

The effectiveness of DMARC will improve significantly as adoption increases. Proving an implementation of DMARC that SMTP utilities like SpamAssassin, amavis, and qpsmtpd can consume will aid adoption.

The list of dependencies appears long because of reporting. If this module is used without reporting, the number of dependencies not included with perl is about 5. See the \[Prereq\] versus \[Prereq / Recommends\] sections in dist.ini.

## Maintainable

Since DMARC is evolving, this implementation aims to be straight forward and dare I say, easy, to alter and extend. The programming style is primarily OO, which carries a small performance penalty but large dividends in maintainability.

When multiple options are available, such as when sending reports via SMTP or HTTP, calls should be made to the parent Send class, to broker the request. When storing reports, calls are made to the Store class, which dispatches to the SQL class. The idea is that if someone desired a data store other than the many provided by perl's DBI class, they could easily implement their own. If you do, please fork it on GitHub and share.

## Fast

If you deploy this in an environment where performance is insufficient, please profile the app and submit a report and preferably, patches.

# SEE ALSO

Mail::DMARC on GitHub: https://github.com/msimerson/mail-dmarc

Mar 13, 2013 Draft: http://tools.ietf.org/html/draft-kucherawy-dmarc-base-00

Mar 30, 2012 Draft: http://www.dmarc.org/draft-dmarc-base-00-02.txt

Best Current Practices: http://tools.ietf.org/html/draft-crocker-dmarc-bcp-03

# HISTORY

The daddy of this perl module was a DMARC module for the qpsmtpd MTA.

Qpsmtpd plugin: https://github.com/smtpd/qpsmtpd/blob/master/plugins/dmarc

# AUTHORS

- Matt Simerson <msimerson@cpan.org>
- Davide Migliavacca <shari@cpan.org>

# CONTRIBUTORS

- Benny Pedersen <me@junc.eu>
- Making GitHub Delicious. <iron@waffle.io>
- Marc Bradshaw <marc@marcbradshaw.net>
- Priyadi Iman Nurcahyo <priyadi@priyadi.net>
- Ricardo Signes <rjbs@cpan.org>
- Ricardo Signes <rjbs@users.noreply.github.com>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2015 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
