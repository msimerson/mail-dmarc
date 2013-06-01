package Mail::DMARC::Report::Send::HTTP;
# VERSION
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
__END__
sub {}

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

=cut
