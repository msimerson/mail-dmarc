package Mail::DMARC;
# ABSTRACT: Perl implementation of DMARC
use strict;
use warnings;

use Carp;

use Mail::DMARC::DNS;
use Mail::DMARC::Policy;
use Mail::DMARC::Result;

=head1 SYNOPSIS

DMARC: a reliable means to authenticate who mail is from.

=cut

sub new {
    my ($class, @args) = @_;
    croak "invalid arguments" if @args % 2 != 0;
    return bless { @args }, $class;
};

sub source_ip {
    return $_[0]->{source_ip} if 1 == scalar @_;
    croak "invalid source_ip" if ! $_[0]->is_valid_ip($_[1]);
    return $_[0]->{source_ip} = $_[1];
};

sub envelope_to {
    return $_[0]->{envelope_to} if 1 == scalar @_;
    croak "invalid envelope_to" if ! $_[0]->is_valid_domain($_[1]);
    return $_[0]->{envelope_to} = $_[1];
};

sub envelope_from {
    return $_[0]->{envelope_from} if 1 == scalar @_;
    croak "invalid envelope_from" if ! $_[0]->is_valid_domain($_[1]);
    return $_[0]->{envelope_from} = $_[1];
};

sub header_from {
    return $_[0]->{header_from} if 1 == scalar @_;
    croak "invalid header_from" if ! $_[0]->is_valid_domain($_[1]);
    return $_[0]->{header_from} = $_[1];
};

sub header_from_raw {
    return $_[0]->{header_from_raw} if 1 == scalar @_;
#croak "invalid header_from_raw: $_[1]" if 'from:' ne lc substr($_[1], 0, 5);
    return $_[0]->{header_from_raw} = $_[1];
};

sub dkim {
    my ($self, $dkim) = @_;
    return $self->{dkim} if ! $dkim;

    if ( ref $dkim && ref $dkim eq 'Mail::DKIM::Verifier' ) {
# A DKIM verifier will have result and signature methods.
        foreach my $s ( $dkim->signatures ) {
            push @{ $self->{dkim} }, {
                domain       => $s->domain,
                selector     => $s->selector,
                result       => $s->result,
                human_result => $s->result_detail,
            };
        };
        return $self->{dkim};
    };

    if ( 'ARRAY' ne ref $dkim ) {
        croak "dkim must be an array reference!";
    };
    return $self->{dkim} = $dkim;
};

sub spf {
    my ($self, @args) = @_;
    return $self->{spf} if 0 == scalar @args;

    if ( scalar @args == 1 && ref $args[0] && ref $args[0] eq 'HASH' ) {
        return $self->{spf} = $args[0];
    };

    croak "invalid arguments" if @args % 2 != 0;
    return $self->{spf} = { @args };
};

sub inputs {
    my $self = shift;
    return {
        backend       => 'perl', # perl or libopendmarc
        report_domain => 'great.co',
        report_org    => 'My Great Company',
    }
};

sub policy {
    my $self = shift;
    $self->{policy} ||= Mail::DMARC::Policy->new();
    return $self->{policy};
};

sub result {
    my $self = shift;
    return $self->{result} if ref $self->{result};
    $self->{result} = Mail::DMARC::Result->new();
    return $self->{result};
};

sub is_valid_ip {
    my ($self, $ip) = @_;
    $self->{dns} ||= Mail::DNS::DNS->new();
    return $self->{dns}->is_valid_ip($ip);
};

sub is_valid_domain {
    my ($self, $domain) = @_;
    $self->{dns} ||= Mail::DMARC::DNS->new();
    return $self->{dns}->is_valid_domain($domain);
};

1;

__END__

sub {};  # for vim automatic code folding

=head1 DESCRIPTION

Determine if:

    a. the header_from domain exists
    b. the header_from domain publishes a DMARC policy
    c. if a policy is found, does the message conform?

=head1 METHODS

=head2 new

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

=head2 source_ip

The remote IP that attempted sending the message. DMARC only uses this data for reporting to domains that request DMARC reports.

=head2 envelope_to

The domain portion of the RFC5321.RcptTo, (aka, the envelope recipient), and the bold portion in the following example:

=over 8

RCPT TO:<user@B<example.com>>

=back

=head2 envelope_from

The domain portion of the RFC5321.MailFrom, (aka, the envelope sender). That is the the bold portion in the following example:

=over 8

MAIL FROM:<user@B<example.com>>

=back

=head2 header_from

The domain portion of the RFC5322.From, aka, the From message header.

=over 8

From: Ultimate Vacation <sweepstakes@B<example.com>>

=back

You can instead pass in the entire From: header with header_from_raw.

=head2 header_from_raw

This retrieves the header_from domain by extracing it from a raw From field/header.  The domain portion is extracted by Mail::DMARC::PurePerl::get_dom_from_header, which is fast, generally effective, but also rather crude. It does have limits, so read the description.

=head2 dkim

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

=head3 domain

The d= parameter in the signature

=head3 selector

The s= parameter in the signature

=head3 result

The validation results of this signature. One of: none, pass, fail, policy, neutral, temperror, or permerror

=head3 human result

Additional information about the DKIM result. This is comparable to Mail::DKIM::Verifier->result_detail.

=head2 spf

The spf method accepts a hashref or named arguments:

    $dmarc->spf(
        domain => 'example.com',
        scope  => 'mfrom',
        result => 'pass',
    );

The SPF domain and result are required for DMARC validation and the scope is used for reporting.

=head3 domain

The SPF checked domain

=head3 scope

The scope of the checked domain: mfrom, helo

=head3 result

The SPF result code: none, neutral, pass, fail, softfail, temperror, or permerror.

=cut
