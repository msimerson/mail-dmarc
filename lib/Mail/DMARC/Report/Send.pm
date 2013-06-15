package Mail::DMARC::Report::Send;
our $VERSION = '1.20130615'; # VERSION
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

=pod

=head1 NAME

Mail::DMARC::Report::Send - report sending dispatch class

=head1 VERSION

version 1.20130615

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

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=back

=head1 CONTRIBUTORS

=over 4

=item *

Benny Pedersen <me@junc.eu>

=item *

ColocateUSA.net <company@colocateusa.net>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by ColocateUSA.com.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

__END__
sub {}

