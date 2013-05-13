package Mail::DMARC::Report::Send;
use strict;
use warnings;

use IO::Compress::Gzip;

use Carp;

use lib 'lib';
use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Send::SMTP;
use Mail::DMARC::Report::Send::HTTP;
use Mail::DMARC::Report::URI;

sub send_rua {
    my ($self, $report, $xml) = @_;

#warn Data::Dumper::Dumper($report);
    my $gz;
    IO::Compress::Gzip::gzip( $xml, \$gz ) or croak "unable to compress";

    my $uri_ref = $self->uri->parse($$report->{policy_published}{rua});
    my $sent = 0;
    foreach my $u_ref ( @$uri_ref ) {
        my $method = $u_ref->{uri};
# TODO: check $u_ref->{max_bytes};
        if ( 'mailto:' eq substr($method,0,7) ) {
            my ($to) = (split /:/, $method)[-1];
            carp "sending mailto $to\n";
            $self->send_via_smtp($to, $report, $gz) and $sent++;
# TODO: check results, append error if failed, delete report if success
        };
        if ( 'http:' eq substr($method,0,5) ) {
            carp "not implemented yet!";
        };
    };
    return $sent;
};

sub human_summary {
    my ($self, $report) = @_;
    return "\n\t This is only a test body. It will get better\n\n";
};

sub send_via_smtp {
    my ($self,$to,$report,$gz) = @_;
    my $rid = $$report->{id};
    my $dom = $$report->{domain};
    return $self->smtp->email(
        to            => $to,
        subject       => $self->smtp->get_subject({report_id=>$rid,policy_domain=>$dom}),
        body          => $self->human_summary($report),
        report        => $gz,
        policy_domain => $dom,
        begin         => $$report->{begin},
        end           => $$report->{end},
        report_id     => $rid,
        );
};

sub smtp {
    my $self = shift;
    return $self->{smtp} if ref $self->{smtp};
    return $self->{smtp} = Mail::DMARC::Report::Send::SMTP->new();
};

sub uri {
    my $self = shift;
    return $self->{uri} if ref $self->{uri};
    return $self->{uri} = Mail::DMARC::Report::URI->new();
};

1;
# ABSTRACT: send a DMARC report object
__END__
sub {}

=head1 DESCRIPTION

Send DMARC reports, via SMTP or HTTP.

=head2 Report Sender

A report sender needs to:

  1. store reports
  2. bundle aggregated reports
  3. format report in XML
  4. gzip the XML
  5. deliver report to Author Domain

=head1 12.2.1 Email

L<Mail::DMARC::Report::Send::SMTP>

=head1 12.2.2. HTTP

L<Mail::DMARC::Report::Send::HTTP>

=head1 12.2.3. Other Methods

Other registered URI schemes may be explicitly supported in later versions.

=cut
