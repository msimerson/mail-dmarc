package Mail::DMARC::Report::Send::HTTP;
use strict;
use warnings;
use feature 'signatures';

our $VERSION = '2.20261110';

use Carp;
use HTTP::Tiny;

use parent 'Mail::DMARC::Base';

sub post( $self, $args ) {
    my $uri = $args->{uri} or croak "missing uri";
    defined $args->{report} or croak "missing report";

    my %headers = ( 'Content-Type' => 'application/gzip' );
    $headers{'Content-Disposition'} = qq{attachment; filename="$args->{filename}"}
        if $args->{filename};

    # 2013 draft 12.2.2: the request SHOULD carry the email Subject
    $headers{Subject} = $args->{subject} if $args->{subject};

    return $self->user_agent->post( "$uri",
        { headers => \%headers, content => $args->{report} } );
}

sub user_agent($self) {
    return $self->{user_agent} //= HTTP::Tiny->new(
        agent      => "Mail-DMARC/$VERSION ",
        timeout    => 60,
        verify_SSL => 1,
    );
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Send::HTTP - utility methods to send reports by HTTP

=head1 VERSION

version 2.20261110

=head1 SYNOPSIS

  my $res = Mail::DMARC::Report::Send::HTTP->new->post(
      {   uri      => 'https://reports.example.com/dmarc',
          report   => $gzipped_xml,
          subject  => 'Report Domain: example.com Submitter: ...',
          filename => 'submitter!example.com!1609459200!1609545600!id.xml.gz',
      }
  );
  print "sent\n" if $res->{success};

=head1 METHODS

=head2 post

POSTs a gzipped aggregate report to an http or https rua URI and returns the
L<HTTP::Tiny> response. Any 2xx response is success. HTTPS certificates are
verified.

=head1 12.2.2. HTTP

Where an "http" or "https" method is requested in a Domain Owner's
URI list, the Mail Receiver MAY encode the data using the
"application/gzip" media type ([GZIP]) or MAY send the Appendix C
data uncompressed or unencoded.

The header portion of the POST or PUT request SHOULD contain a
Subject field as described in Section 12.2.1.

HTTP permits the use of Content-Transfer-Encoding to upload gzip
content using the POST or PUT instruction after translating the
content to 7-bit ASCII.

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

This software is copyright (c) 2026 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
