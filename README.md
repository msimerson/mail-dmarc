# NAME

Mail::DMARC - Perl implementation of DMARC

# VERSION

version 0.20130522

# SYNOPSIS

DMARC: Domain-based Message Authentication, Reporting and Conformance

    my $dmarc = Mail::DMARC->new( "see L<new|#new> for required args");
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

    by MTAs and filtering tools such as SpamAssassin to validate that incoming messages are aligned with the purported senders policies.

    by an email sender that wishes to receive DMARC reports from other mail servers.

When a message arrives via SMTP, the MTA or filtering application can pass in a small amount of metadata about the connection (envelope details, SPF results, and DKIM results) to Mail::DMARC. When the __validate__ method is called, the Mail::DMARC will determine if:

    a. the header_from domain exists
    b. the header_from domain publishes a DMARC policy
    c. if not, end processing
    d. does the message conform to the published policy?
    e. did the policy request reporting? If so, save details.

The validation results are stored in a [Mail::DMARC::Result](http://search.cpan.org/perldoc?Mail::DMARC::Result) object. If the author domain requested a report, it was saved via [Mail::DMARC::Report::Store](http://search.cpan.org/perldoc?Mail::DMARC::Report::Store). A SQL implementation is provided and tested with SQLite and MySQL. ANSI SQL queries syntax is preferred, making it straight forward to extend to other RDBMS.

There is more information available in the $result object. See [Mail::DMARC::Result](http://search.cpan.org/perldoc?Mail::DMARC::Result) for complete details.

# CLASSES

[Mail::DMARC](http://search.cpan.org/perldoc?Mail::DMARC) - the perl interface for DMARC

[Mail::DMARC::Policy](http://search.cpan.org/perldoc?Mail::DMARC::Policy) - a DMARC policy

[Mail::DMARC::PurePerl](http://search.cpan.org/perldoc?Mail::DMARC::PurePerl) - Pure Perl implementation of DMARC

[Mail::DMARC::Result](http://search.cpan.org/perldoc?Mail::DMARC::Result) - the results of applying policy

[Mail::DMARC::Report](http://search.cpan.org/perldoc?Mail::DMARC::Report) - Reporting: the R in DMARC

    [Mail::DMARC::Report::Send](http://search.cpan.org/perldoc?Mail::DMARC::Report::Send) - send reports via SMTP & HTTP

    [Mail::DMARC::Report::Receive](http://search.cpan.org/perldoc?Mail::DMARC::Report::Receive) - receive and store reports from email, HTTP

    [Mail::DMARC::Report::Store](http://search.cpan.org/perldoc?Mail::DMARC::Report::Store) - a persistent data store for aggregate reports

    [Mail::DMARC::Report::View](http://search.cpan.org/perldoc?Mail::DMARC::Report::View) - CLI and CGI methods for viewing reports

[Mail::DMARC::libopendmarc](http://search.cpan.org/~shari/Mail-DMARC-opendmarc) - an XS implementation using libopendmarc

# METHODS

## new

Create an empty DMARC object. Then populate it and run the request:

    my $dmarc = Mail::DMARC->new;
    $dmarc->source_ip('192.0.1.1');
    $dmarc->envelope_to('recipient.example.com');
    $dmarc->envelope_from('sender.example.com');
    $dmarc->header_from('sender.example.com');
    $dmarc->dkim( $dkim_verifier );
    $dmarc->spf(
        domain => 'example.com',
        scope  => 'mfrom',
        result => 'pass',
            );
    my $result = $dmarc->validate();

Alternatively, you can pass in all the required parameters in one shot:

    my $dmarc = Mail::DMARC->new(
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

    RCPT TO:<user@__example.com__\>

## envelope\_from

The domain portion of the RFC5321.MailFrom, (aka, the envelope sender). That is the the bold portion in the following example:

    MAIL FROM:<user@__example.com__\>

## header\_from

The domain portion of the RFC5322.From, aka, the From message header.

    From: Ultimate Vacation <sweepstakes@__example.com__\>

You can instead pass in the entire From: header with header\_from\_raw.

## header\_from\_raw

Retrieve the header\_from domain by parsing it from a raw From field/header. The domain portion is extracted by [get\_dom\_from\_header](http://search.cpan.org/perldoc?Mail::DMARC::PurePerl\#get\_dom\_from\_header), which is fast, generally effective, but also rather crude. It has limits, so read the description.

## dkim

The dkim method accepts an array reference. Each array element represents a DKIM signature in the message and consists of the 4 keys shown in this example:

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

If you used Mail::DKIM::Verifier to validate the message, just pass in the Mail::DKIM::Verifier object that processed the message:

    $dmarc->dkim( $dkim_verifier );

### domain

The d= parameter in the signature

### selector

The s= parameter in the signature

### result

The validation results of this signature. One of: none, pass, fail, policy, neutral, temperror, or permerror

### human result

Additional information about the DKIM result. This is comparable to Mail::DKIM::Verifier->result\_detail.

## spf

The spf method accepts a hashref or named arguments:

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

# HISTORY

The daddy of this perl module was a DMARC module for the qpsmtpd MTA.

Qpsmtpd plugin: https://github.com/qpsmtpd-dev/qpsmtpd-dev/blob/master/plugins/dmarc

# AUTHORS

- Matt Simerson <msimerson@cpan.org>
- Davide Migliavacca <shari@cpan.org>

# CONTRIBUTOR

ColocateUSA.net <company@colocateusa.net>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by ColocateUSA.com.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
