# SYNOPSIS

DMARC: Domain-based Message Authentication, Reporting and Conformance

A reliable means to authenticate who mail is from, at internet scale.

# DESCRIPTION

Determine if:

    a. the header_from domain exists
    b. the header_from domain publishes a DMARC policy
    c. does the message conform to the published policy?

Results of DMARC processing are stored in a [Mail::DMARC::Result](http://search.cpan.org/perldoc?Mail::DMARC::Result) object.

# HOW TO USE

    my $dmarc = Mail::DMARC->new( "see L<new|#new> for required args");
    my $result = $dmarc->verify();

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

There's a lot of information available in the $result object. See [Mail::DMARC::Result](http://search.cpan.org/perldoc?Mail::DMARC::Result) page for complete details.

# CLASSES

[Mail::DMARC](http://search.cpan.org/perldoc?Mail::DMARC) - A perl implementation of the DMARC draft

[Mail::DMARC::Policy](http://search.cpan.org/perldoc?Mail::DMARC::Policy) - a DMARC policy, as published or retrieved via DNS

[Mail::DMARC::PurePerl](http://search.cpan.org/perldoc?Mail::DMARC::PurePerl) - a perl DMARC implementation

[Mail::DMARC::Result](http://search.cpan.org/perldoc?Mail::DMARC::Result) - results of DMARC processing

[Mail::DMARC::Report](http://search.cpan.org/perldoc?Mail::DMARC::Report) - Reporting: the R in DMARC

    [Mail::DMARC::Report::Send](http://search.cpan.org/perldoc?Mail::DMARC::Report::Send) - deliver formatted reports via SMTP & HTTP

    [Mail::DMARC::Report::Receive](http://search.cpan.org/perldoc?Mail::DMARC::Report::Receive) - parse incoming email and HTTP reports to store

    [Mail::DMARC::Report::Store](http://search.cpan.org/perldoc?Mail::DMARC::Report::Store) - a persistent data store for DMARC reports

    [Mail::DMARC::Report::View](http://search.cpan.org/perldoc?Mail::DMARC::Report::View) - CLI and (eventually) CGI methods for report viewing

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
    my $result = $dmarc->verify();

Alternatively, you can pass in all the required parameters in one shot:

    my $dmarc = Mail::DMARC->new(
            source_ip     => '192.0.1.1',
            envelope_to   => 'example.com',
            envelope_from => 'cars4you.info',
            header_from   => 'yahoo.com',
            dkim          => $dkim_results,  # same format
            spf           => $spf_results,   # as previous example
            );
    my $result = $dmarc->verify();



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

This retrieves the header\_from domain by extracing it from a raw From field/header.  The domain portion is extracted by Mail::DMARC::PurePerl::get\_dom\_from\_header, which is fast, generally effective, but also rather crude. It does have limits, so read the description.

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
