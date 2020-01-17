package Mail::DMARC::Report::Send::SMTP;
use strict;
use warnings;

our $VERSION = '1.20200116';

use Carp;
use English '-no_match_vars';
use Email::MIME;
#use Mail::Sender;  # something to consider
use Sys::Hostname;
use POSIX;

use parent 'Mail::DMARC::Base';

sub get_domain_mx {
    my ( $self, $domain ) = @_;
    print "getting MX for $domain\n";
    my $query;
    eval {
        $query = $self->get_resolver->send( $domain, 'MX' ) or return [];
    } or print $@;

    if ( ! $query ) {
        print "\terror:\n\t$@";
        return [];
    };

    my @mx;
    for my $rr ( $query->answer ) {
        next if $rr->type ne 'MX';
        push @mx, { pref => $rr->preference, addr => $rr->exchange };
        print $rr->exchange if $self->verbose;
    }
    if ( $self->verbose ) {
        print "found " . scalar @mx . "MX exchanges\n";
    };
    return \@mx;
}

sub connect_smtp {
    my ( $self, $to ) = @_;

    my $smtp = Net::SMTP->new(
        [ $self->get_smtp_hosts($to) ],
        Timeout         => 30,
        Port            => 25,
        Hello           => $self->get_helo_hostname,
        Debug           => $self->verbose ? 1 : 0,
        )
        or do {
            carp "SMTP connection failed\n";
            return;
        };

    return $smtp;
};

sub connect_smtp_tls {
    my ($self, $to) = @_;

    # lazy load, so test can load this file w/o dep. installed
    eval "require Net::SMTPS" or return;  ## no critic (Eval)

    my $smtp = Net::SMTPS->new(
        [ $self->get_smtp_hosts($to) ],
        Timeout         => 32,
        Port            => $self->config->{smtp}{smarthost} ? 587 : 25,
        Hello           => $self->get_helo_hostname,
        Debug           => $self->verbose ? 1 : 0,
        SSL_verify_mode => 0,
        )
        or do {
            warn "SSL connection failed\n"; ## no critic (Carp)
            return;
        };

    my $tls_supported = $smtp->supports('STARTTLS');
    if ( ! defined $tls_supported ) {
        warn "server does not support STARTTLS\n"; ## no critic (Carp)
        return;
    }

    $smtp->starttls();
    if ( $smtp->code =~ /^5/ ) {
        warn "server failed STARTTLS upgrade\n"; ## no critic (Carp)
        return;
    }
    $smtp->hello($self->get_helo_hostname);

    my $c = $self->config->{smtp};
    if ( $c->{smarthost} && $c->{smartuser} && $c->{smartpass} ) {
        $smtp->auth( $c->{smartuser}, $c->{smartpass} ) or do {
            carp "auth attempt for $c->{smartuser} failed";
        };
    }

    return $smtp;
};

sub get_smtp_hosts {
    my $self = shift;
    my $email = shift or croak "missing email!";

    if ( $self->config->{smtp}{smarthost} ) {
        return $self->config->{smtp}{smarthost};
    }

    my ($domain) = ( split /@/, $email )[-1];
    my @mx = map  { $_->{addr} }
             sort { $a->{pref} <=> $b->{pref} }
             @{ $self->get_domain_mx($domain) };

    push @mx, $domain;
    print "\tfound " . scalar @mx . " MX for $email\n" if $self->verbose;
    return @mx;
}

sub get_subject {
    my ( $self, $agg_ref ) = @_;


    my $rid = $$agg_ref->metadata->report_id || time;
    my $id = POSIX::strftime( "%Y.%m.%d.", localtime ) . $rid;
    my $us = $self->config->{organization}{domain};
    if ($us eq 'example.com') {
        die "Please update mail-dmarc.ini";
    }
    my $pol_dom = $$agg_ref->policy_published->domain;
    return "Report Domain: $pol_dom Submitter: $us Report-ID:$id";
}

sub human_summary {
    my ( $self, $agg_ref ) = @_;

    my $records = scalar @{ $$agg_ref->{record} };
    my $OrgName = $self->config->{organization}{org_name};
    my $pass = grep { 'pass' eq $_->{row}{policy_evaluated}{dkim}
                   || 'pass' eq $_->{row}{policy_evaluated}{spf}  }
                   @{ $$agg_ref->{record} };
    my $fail = grep { 'pass' ne $_->{row}{policy_evaluated}{dkim}
                   && 'pass' ne $_->{row}{policy_evaluated}{spf} }
                   @{ $$agg_ref->{record} };
    my $ver  = $Mail::DMARC::Base::VERSION || ''; # undef in author environ
    my $from = $$agg_ref->{policy_published}{domain} or croak;

    return <<"EO_REPORT"

This is a DMARC aggregate report for $from

$records records.
$pass passed.
$fail failed.

Submitted by $OrgName
Generated with Mail::DMARC $ver

EO_REPORT
        ;
}

sub get_filename {
    my ( $self, $agg_ref ) = @_;

    #  2013 DMARC Draft, 12.2.1 Email
    #
    #   filename = receiver "!" policy-domain "!" begin-timestamp "!"
    #              end-timestamp [ "!" unique-id ] "." extension
    #   filename="mail.receiver.example!example.com!1013662812!1013749130.gz"
    return join( '!',
        $self->config->{organization}{domain},
        $$agg_ref->policy_published->domain,
        $$agg_ref->metadata->begin,
        $$agg_ref->metadata->end,
        $$agg_ref->metadata->report_id || time,
    ) . '.xml';
}

sub assemble_message {
    my ( $self, $agg_ref, $to, $shrunk ) = @_;

    my $filename = $self->get_filename($agg_ref);
# WARNING: changes made here MAY affect Send::compress. Check it!
#   my $cf       = ( time > 1372662000 ) ? 'gzip' : 'zip';   # gz after 7/1/13
    my $cf       = 'gzip';
      $filename .= $cf eq 'gzip' ? '.gz' : '.zip';

    my @parts    = Email::MIME->create(
        attributes => {
            content_type => "text/plain",
            disposition  => "inline",
            charset      => "US-ASCII",
        },
        body => $self->human_summary( $agg_ref ),
    ) or croak "unable to add body!";

    push @parts,
        Email::MIME->create(
        attributes => {
            filename     => $filename,
            content_type => "application/$cf",
            encoding     => "base64",
            name         => $filename,
        },
        body => $shrunk,
        ) or croak "unable to add report!";

    my $email = Email::MIME->create(
        header_str => [
            From => $self->config->{organization}{email},
            To   => $to,
            Date => $self->get_timestamp_rfc2822,
            Subject => $self->get_subject( $agg_ref ),
        ],
        parts => [@parts],
    ) or croak "unable to assemble message\n";

    return $email->as_string;
}

sub get_timestamp_rfc2822 {
    my ($self, @args) = @_;
    my @ts = scalar @args ? @args : localtime;
    my $locale = setlocale(LC_CTYPE);
    setlocale(LC_ALL, 'C');
    my $timestamp = POSIX::strftime( '%a, %d %b %Y %H:%M:%S %z', @ts );
    setlocale(LC_ALL, $locale);
    return $timestamp;
}

sub get_helo_hostname {
    my $self = shift;
    my $host = $self->config->{smtp}{hostname};
    return $host if $host && $host ne 'mail.example.com';
    return Sys::Hostname::hostname;
};

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Send::SMTP - utility methods for sending reports via SMTP

=head1 VERSION

version 1.20200116

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

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=item *

Marc Bradshaw <marc@marcbradshaw.net>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2020 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

