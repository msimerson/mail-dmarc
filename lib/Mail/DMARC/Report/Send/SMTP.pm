package Mail::DMARC::Report::Send::SMTP;
use strict;
use warnings;

use Carp;
use English '-no_match_vars';
use Email::MIME;
use Net::SMTPS;
use Sys::Hostname;
use POSIX;

use parent 'Mail::DMARC::Base';

sub email {
    my ($self, @args) = @_;
    croak "invalid args to email" if @args % 2;
    my %args = @args;

    my @required = qw/ to subject body report policy_domain begin end /;
    my @optional = qw/ report_id /;
    my %all = map { $_ => 1 } ( @required, @optional );
    foreach ( keys %args ) { croak "unknown arg $_" if ! $all{$_} };

    foreach my $req ( @required ) {
        croak "missing required header: $req" if ! $args{$req};
    };

    my $cc = $self->config->{smtp}{cc};
    if ( $cc && $cc ne 'set.this@for.a.while.example.com' ) {
        my $original_to = $args{to};
        $args{to} = $cc;
        $self->via_net_smtp( \%args );
        $args{to} = $original_to;
    };
    return $self->via_net_smtp(\%args);

#    eval { require MIME::Lite; }; ## no critic (Eval)
#    if ( !$EVAL_ERROR ) {
#        return 1 if $self->via_mime_lite( \%args );
#    }

#    carp "failed to send with MIME::Lite.";
#   croak "unable to send message";
};

sub via_net_smtp {
    my ($self, $args) = @_;

    my $to_domain = $args->{domain} = $self->get_to_dom($args);
    my $hosts = $self->get_smtp_hosts($to_domain);
    my @try_mx = map { $_->{addr} }
        sort { $a->{pref} <=> $b->{pref} } @$hosts;
    push @try_mx, $to_domain;  # might be 0 MX records

    my $c = $self->config->{smtp};
    my $hostname = $c->{hostname};
    if ( ! $hostname || $hostname eq 'mail.example.com' ) {
        $hostname = Sys::Hostname::hostname;
    };
    my $body = $self->_assemble_message($args);

    my $err = "found " . scalar @try_mx . " MX";
    my $smtp = Net::SMTPS->new(
            [ @try_mx ],
            Timeout => 10,
            Port    => 25,
            Hello   => $hostname,
            doSSL   => 'starttls',
            SSL_verify_mode => 'SSL_VERIFY_NONE',
            )
        or do {
            carp "$err but 0 available for $to_domain\n";
            return;
        };

    carp "deliving message to $args->{to}\n";

    if ( $c->{smarthost} && $c->{smartuser} && $c->{smartpass} ) {
        $smtp->auth($c->{smartuser}, $c->{smartpass} ) or do {
            carp "$err but auth attempt for $c->{smartuser} failed";
        };
    };
    my $from = $self->config->{organization}{email};
    $smtp->mail($from) or do {
        carp "MAIL FROM $from rejected\n";
        $smtp->quit;
        return;
    };
    $smtp->recipient($args->{to}) or do {
        carp "RCPT TO $args->{to} rejected\n";
        $smtp->quit;
        return;
    };
    $smtp->data( $body ) or do {
        carp "DATA for $args->{domain} rejected\n";
        return;
    };
    $smtp->quit;
    return 1;
};

sub get_domain_mx {
    my ($self, $domain) = @_;
    my $res = $self->get_resolver();
    my $query = $res->query($domain, 'MX') or return [];
    my @mx;
    for my $rr ($query->answer) {
        next if $rr->type ne 'MX';
        push @mx, { pref=> $rr->preference, addr=> $rr->exchange };
    }
    return \@mx;
};

sub get_to_dom {
    my ($self, $args) = @_;
    croak "invalid args" if 'HASH' ne ref $args;
    my ($to_dom) = (split /@/, $args->{to} )[-1];
    return $to_dom;
};

sub get_smtp_hosts {
    my $self = shift;
    my $domain = shift or croak "missing domain!";

    if ( $self->config->{smtp}{smarthost} ) {
        return [ {addr => $self->config->{smtp}{smarthost} } ];
    };

    return $self->get_domain_mx($domain);
};

sub get_subject {
    my ($self, $args) = @_;

=head2 SUBJECT FIELD

The RFC5322.Subject field for individual report submissions SHOULD conform to the following ABNF:

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

=cut

    my $id = POSIX::strftime("%Y.%m.%d.", localtime) . ($args->{report_id} || time);
    my $us = $self->config->{organization}{domain};
    return "Report Domain: $args->{policy_domain} Submitter: $us Report-ID: <$id>";
};

sub get_filename {
    my ($self, $args) = @_;

#  2013 DMARC Draft, 12.2.1 Email
#
#   filename = receiver "!" policy-domain "!" begin-timestamp "!"
#              end-timestamp [ "!" unique-id ] "." extension
#   filename="mail.receiver.example!example.com!1013662812!1013749130.gz"
    return join( '!',
            $self->config->{organization}{domain},
            $args->{policy_domain},
            $args->{begin},
            $args->{end},
            $args->{report_id} || time,
            ) . '.xml.gz';
};

sub _assemble_message {
    my ($self, $args) = @_;

    my $filename = $self->get_filename($args);
    my @parts = Email::MIME->create(
                attributes => {
                    content_type => "text/plain",
                    disposition  => "inline",
                    charset      => "US-ASCII",
                },
                body => $args->{body},
            ) or croak "unable to add body!";

    push @parts, Email::MIME->create(
                attributes => {
                    filename     => $filename,
                    content_type => "application/gzip",
                    encoding     => "base64",
                    name         => $filename,
                },
                body => $args->{report},
            ) or croak "unable to add report!";

    my $email = Email::MIME->create(
            header_str => [
                From => $self->config->{organization}{email},
                To   => $args->{to},
                Date => strftime('%a, %d %b %Y %H:%M:%S %z', localtime), # RFC 2822 format
                Subject => $args->{subject},
            ],
            parts => [ @parts ],
        ) or croak "unable to assemble message\n";

    return $email->as_string;
}

sub via_mail_sender {
};

sub via_mime_lite {
    my $self = shift;
    my $args = shift;

    #warn "sending email with MIME::Lite\n";
    my $message = MIME::Lite->new(
        From    => $self->config->{organization}{email},
        To      => $args->{to},
        Subject => $args->{subject},
        Type    => $args->{type} || 'multipart/alternative',
    );

    $message->attach( Type => 'TEXT', Data => $args->{body} ) or croak;
    $message->attach( Type => 'application/gzip', Data => $args->{report} ) or croak;

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

=cut
