package Mail::DMARC::Report::Send::HTTP;
our $VERSION = '1.20130604'; # VERSION
use strict;
use warnings;

use Carp;

#use Data::Dumper;
use Net::HTTP;

use parent 'Mail::DMARC::Base';

sub post {
    my ( $self, $uri, $report, $gz ) = @_;

    carp "http send incomplete!";
    return;

    # TODO: test
## no critic (Unreachable)
    my $ver = $Mail::DMARC::VERSION;
    my $s = Net::HTTP->new( Host => $uri->host ) or croak $@;
    $s->write_request(
        POST         => $uri->path,
        'User-Agent' => "Mail::DMARC/$ver"
    );
    my ( $code, $mess, %h ) = $s->read_response_headers;

    while (1) {
        my $buf;
        my $n = $s->read_entity_body( $buf, 1024 );
        croak "read failed: $!" unless defined $n;
        last unless $n;
        print $buf;
        return 1;
    }
    return 0;
}

1;

# ABSTRACT: send DMARC reports via HTTP

=pod

=head1 NAME

Mail::DMARC::Report::Send::HTTP - send DMARC reports via HTTP

=head1 VERSION

version 1.20130604

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

=back

=head1 CONTRIBUTOR

ColocateUSA.net <company@colocateusa.net>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by ColocateUSA.com.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

__END__
sub {}

