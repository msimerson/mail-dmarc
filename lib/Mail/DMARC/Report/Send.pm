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
