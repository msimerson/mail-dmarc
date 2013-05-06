# SYNOPSIS

DMARC: Domain-based Message Authentication, Reporting and Conformance

A reliable means to authenticate who mail is from, at internet scale.

# CLASSES

[Mail::DMARC](http://search.cpan.org/perldoc?lib#Mail/DMARC.pm) - A perl implementation of the DMARC draft

[Mail::DMARC::DNS](http://search.cpan.org/perldoc?lib#Mail/DMARC/DNS.pm) - DNS functions used in DMARC

[Mail::DMARC::Policy](http://search.cpan.org/perldoc?lib#Mail/DMARC/Policy.pm) - a DMARC record in object format

[Mail::DMARC::PurePerl](http://search.cpan.org/perldoc?lib#Mail/DMARC/PurePerl.pm) - a DMARC implementation

\* [Mail::DMARC::Report](http://search.cpan.org/perldoc?lib#Mail/DMARC/Report.pm)
\* [Mail::DMARC::Report::AFRF](http://search.cpan.org/perldoc?lib#Mail/DMARC/Report/AFRF.pm)
\* [Mail::DMARC::Report::IODEF](http://search.cpan.org/perldoc?lib#Mail/DMARC/Report/IODEF.pm)

[Mail::DMARC::URI](http://search.cpan.org/perldoc?lib#Mail/DMARC/URI.pm) - a DMARC reporting URI

\* [Mail::DMARC::Result](http://search.cpan.org/perldoc?lib#Mail/DMARC/Result.pm)
\* [Mail::DMARC::Result::Evaluated](http://search.cpan.org/perldoc?lib#Mail/DMARC/Result/Evaluated.pm)

[Mail::DMARC::libopendmarc](http://search.cpan.org/~shari/Mail-DMARC-opendmarc) - an XS implementation using libopendmarc

# DESCRIPTION

Determine if:

    a. the header_from domain exists
    b. the header_from domain publishes a DMARC policy
    c. if a policy is found, does the message conform?

# METHODS

## new

Create a new empty DMARC object. Then populate it and run the request:

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
            dkim          => $dkim_results,
            spf           => $spf_results,
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
