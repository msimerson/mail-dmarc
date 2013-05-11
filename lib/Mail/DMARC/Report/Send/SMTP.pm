package Mail::DMARC::Report::Send::SMTP;
use strict;
use warnings;

use Carp;
use English '-no_match_vars';
use Net::SMTPS;
use Sys::Hostname;
use POSIX;

use parent 'Mail::DMARC::Base';
use Mail::DMARC::DNS;

sub email {
    my ($self, @args) = @_;
    my %args = @args;

    my @required = qw/ to from subject body /;
    my @optional = qw/ cc type smarthost /;
    my %all = map { $_ => 1 } ( @required, @optional );
    foreach ( keys %args ) { croak "unknown arg $_" if ! $all{$_} };

    foreach my $req ( @required ) {
        croak "missing required header: $req" if ! $args{$req};
    };

    return 1 if $self->net_smtp(\@args);

    eval { require MIME::Lite; }; ## no critic (Eval)
    if ( !$EVAL_ERROR ) {
        return 1 if $self->_email_via_mime_lite( \%args );
    }

    carp "failed to load MIME::Lite. Trying Email::Send.";

    eval { require Email::Send; }; ## no critic (Eval)
    if ( !$EVAL_ERROR ) {
        return 1 if $self->_email_via_email_send( \%args );
    }

    carp "failed to load Email::Send. Trying Mail::Send.";

    eval { require Mail::Send; }; ## no critic (Eval)
    if ( !$EVAL_ERROR ) {
        return 1 if $self->_email_via_mail_send( \%args );
    }

    croak "unable to send message";
};

sub net_smtp {
    my ($self, $args) = @_;

    my $to_domain = $args->{domain} = $self->get_to_dom($args);
    my $hosts = $self->get_smtp_hosts($to_domain);
    my @try_mx = map { $_->{addr} }
        sort { $a->{pref} <=> $b->{pref} } @$hosts;

#print "mx: $_->{pref} $_->{addr}\n";
#warn Data::Dumper::Dumper($hosts);
#warn Data::Dumper::Dumper(\@try_mx);
#return;
    my $conf = $self->config->{smtp};
    my $hostname = $conf->{hostname};
    if ( ! $hostname || $hostname eq 'mail.example.com' ) {
        $hostname = Sys::Hostname::hostname;
    };
    $args->{me} = $hostname;

    my $smtp = Net::SMTPS->new(
            [ @try_mx ],
            Timeout => 10,
            Port    => $to_domain eq 'tnpi.net' ? 587 : 25,
            Hello   => $hostname,
            doSSL   => 'starttls',
            )
        or do {
            carp "no MX available for $to_domain\n";
            return;
        };

    if ( $conf->{smarthost} && $conf->{smartuser} && $conf->{smartpass} ) {
        $smtp->auth($conf->{smartuser}, $conf->{smartpass} ) or do {
            carp "auth attempt for $conf->{smartuser} failed";
        };
    };
    $smtp->mail($args->{from}) or do {
        carp "MAIL FROM $args->{from} rejected\n";
        $smtp->quit;
        return;
    };
    $smtp->recipient($args->{to}) or do {
        carp "RCPT TO $args->{to} rejected\n";
        $smtp->quit;
        return;
    };
    $smtp->data($self->_assemble_message($args)) or do {
        return;
        carp "DATA for $args->{domain} rejected\n";
    };
    $smtp->quit;
    return 1;
};

sub get_to_dom {
    my ($self, $args) = @_;
    my ($to_dom) = (split /@/, $args->{to} )[-1];
    return $to_dom;
};

sub get_smtp_hosts {
    my $self = shift;
    my $domain = shift or croak "missing domain!";

    if ( $self->config->{smtp}{smarthost} ) {
        return [ {addr => $self->config->{smtp}{smarthost} } ];
    };

    $self->{dns} ||= Mail::DMARC::DNS->new();
    return $self->{dns}->get_domain_mx($domain);
};

sub _assemble_message {
    my ($self, $args) = @_;

    my $ds = strftime('%a, %d %b %Y %H:%M:%S %z', localtime);
    my $message = <<"EO_MSG"
From: $args->{from}
Date: $ds
X-Date: Fri, Feb 15 2002 16:54:30 -0800
To: $args->{to}
Subject: Report Domain: $args->{domain}
    Submitter: $args->{me}
    Report-ID: <2013.05.11.1>
MIME-Version: 1.0
Content-Type: multipart/alternative;
    boundary="----=_NextPart_000_024E_01CC9B0A.AFE54C00"
Content-Language: en-us

This is a multipart message in MIME format.

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

This is an aggregate report from $args->{me}.

------=_NextPart_000_024E_01CC9B0A.AFE54C00
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
    filename="mail.receiver.example!example.com!
            1013662812!1013749130.gz"

<gzipped content of report>

------=_NextPart_000_024E_01CC9B0A.AFE54C00--
EO_MSG
;
};

sub _email_via_mail_sender {
};

sub _email_via_mime_lite {
    my $self = shift;
    my $args = shift;

    #warn "sending email with MIME::Lite\n";
    my $message = MIME::Lite->new(
        From    => $args->{from},
        To      => $args->{to},
        Cc      => $args->{cc},
        Subject => $args->{subject},
        Type    => $args->{type} || 'multipart/alternative',
    );

    $message->attach( Type => 'TEXT', Data => $args->{body} ) or croak;

    #warn "attached message\n";

    if ( $args->{body_html} ) {
        $message->attach( Type => 'text/html', Data => $args->{body_html} )
            or croak;
    }

    my $smart_host = $args->{smart_host};
    if ($smart_host) {
        #warn "using smart_host $smart_host\n";
        eval { $message->send( 'smtp', $smart_host, Timeout => 20 ) }; ## no critic (Eval)
        if ( !$EVAL_ERROR ) {
            #warn "sent using MIME::Lite and smart host $smart_host\n";
            return 1;
        }
        carp "failed to send using MIME::Lite to $smart_host\n";
    }

    eval { $message->send('smtp'); }; ## no critic (Eval)
    if ( !$EVAL_ERROR ) {
        return 1;
    }

    eval { $message->send(); }; ## no critic (Eval)
    if ( !$EVAL_ERROR ) {
        return 1;
    }

    return;
}

sub _email_via_email_send {
    my $self = shift;
    my $args = shift;

    my %m_args = ( mailer => 'SMTP', );
    if ( $args->{smart_host} ) {
        $m_args{mailer_args} = [ Host => $args->{smart_host} ];
    }

    my $sender = Email::Send->new( \%m_args );

    my $message = <<"__MESSAGE__";
To: $args->{to}
From: $args->{from}
Subject: $args->{subject}

$args->{body}

__MESSAGE__

    $message .= "\n\n $args->{body_html} \n\n" if $args->{body_html};

    return 1 if $sender->send($message);
    return;
}

sub _email_via_mail_send {

    my $self = shift;
    my $args = shift;

    my $msg = Mail::Send->new;

    $msg->subject( $args->{subject} );
    $msg->to( $args->{to} );

    my $content = $msg->open;

    print $content "\n\n $args->{body} \n\n";
    print $content "$args->{body_html} \n\n" if $args->{body_html};

    return $content->close;
}

1;
# ABSTRACT: send DMARC reports via SMTP
__END__
sub {}

=head1 12.2.1 Email

In the case of a "mailto" URI, the Mail Receiver SHOULD communicate
reports using the method described in [STARTTLS].

The message generated by the Mail Receiver must be a [MIME] formatted
[MAIL] message.  The aggregate report itself MUST be included in one
of the parts of the message.  A human-readable portion MAY be
included as a MIME part (such as a text/plain part).

The aggregate data MUST be an XML file subjected to GZIP compression.
The aggregate data MUST be present using the media type "application/
gzip", and the filenames SHOULD be constructed using the following
ABNF:

     filename = receiver "!" policy-domain "!" begin-timestamp "!"
                end-timestamp [ "!" unique-id ] "." extension

     unique-id = token
              ; "token" is imported from [MIME]

     receiver = domain
              ; imported from [MAIL]

     policy-domain = domain

     begin-timestamp = 1*DIGIT
                     ; seconds since 00:00:00 UTC January 1, 1970
                     ; indicating start of the time range contained
                     ; in the report

     end-timestamp = 1*DIGIT
                   ; seconds since 00:00:00 UTC January 1, 1970
                   ; indicating end of the time range contained
                   ; in the report

     extension = "xml" / "gzip"

   For the GZIP file itself, the extension MUST be "gz"; for the XML
   report, the extension MUST be "xml".

=head2 SUBJECT FIELD

The RFC5322.Subject field for individual report submissions SHOULD
conform to the following ABNF:

   dmarc-subject = %x52.65.70.6f.72.74 1*FWS    ; "Report"
                   %x44.6f.6d.61.69.6e.3a 1*FWS ; "Domain:"
                   domain-name 1*FWS            ; from RFC6376
                   %x53.75.62.6d.69.74.74.65.72.3a ; "Submitter:"
                   1*FWS domain-name 1*FWS
                   %x52.65.70.6f.72.74.2d.49.44.3a ; "Report-ID:"
                   msg-id                       ; from RFC5322

The first domain-name indicates the DNS domain name about which the
report was generated.  The second domain-name indicates the DNS
domain name representing the Mail Receiver generating the report.
The purpose of the Report-ID: portion of the field is to enable the
Domain Owner to identify and ignore duplicate reports that might be
sent by a Mail Receiver.

This transport mechanism potentially encounters a problem when
feedback data size exceeds maximum allowable attachment sizes for
either the generator or the consumer.  See Section 12.2.4 for further
discussion.

=cut
