package Mail::DMARC::Report::Send;
# VERSION
use strict;
use warnings;

use lib 'lib';
use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Send::SMTP;
use Mail::DMARC::Report::Send::HTTP;

sub http {
    my $self = shift;
    return $self->{http} if ref $self->{http};
    return $self->{http} = Mail::DMARC::Report::Send::HTTP->new();
}

sub smtp {
    my $self = shift;
    return $self->{smtp} if ref $self->{smtp};
    return $self->{smtp} = Mail::DMARC::Report::Send::SMTP->new();
}

sub too_big_report {
    my ( $self, $arg_ref ) = @_;

    my $OrgName   = $self->config->{organization}{org_name};
    my $Domain    = $self->config->{organization}{domain};
    my $ver       = $Mail::DMARC::Base::VERSION || ''; # undef in author environ
    my $uri       = $arg_ref->{uri};
    my $bytes     = $arg_ref->{report_bytes};
    my $report_id = $arg_ref->{report_id};
    my $rep_domain= $arg_ref->{report_domain};
    my $date      = $self->smtp->get_timestamp_rfc2822;

    return <<"EO_TOO_BIG"

This is a 'too big' DMARC notice. The aggregate report was NOT delivered.

Report-Date: $date
Report-Domain: $rep_domain
Report-ID: $report_id
Report-Size: $bytes
Submitter: $Domain
Submitting-URI: $uri

Submitted by $OrgName
Generated with Mail::DMARC $ver

EO_TOO_BIG
        ;
}

1;

# ABSTRACT: report sending dispatch class
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

This class and subclasses provide methods used by L<dmarc_send_reports>.

=head1 12.2.1 Email

L<Mail::DMARC::Report::Send::SMTP>

=head1 12.2.2. HTTP

L<Mail::DMARC::Report::Send::HTTP>

=head1 12.2.3. Other Methods

Other registered URI schemes may be explicitly supported in later versions.

=cut
