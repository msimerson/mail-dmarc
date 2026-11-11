package Mail::DMARC::Report::Send::HTTP;
use strict;
use warnings;
use feature 'signatures';

our $VERSION = '2.20261110';

use Carp;
use HTTP::Tiny;
use Socket qw( AF_INET AF_INET6 SOCK_STREAM getaddrinfo inet_ntop inet_pton
    unpack_sockaddr_in unpack_sockaddr_in6 );
use URI;

use parent 'Mail::DMARC::Base';

my $MAX_ERROR_BODY = 4096;

# The rua URI comes from the sender's DNS, so a same-domain http rua could
# otherwise aim POSTs at services on the reporter's own network.
my @NON_PUBLIC = map { _network($_) } qw(
    0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
    192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
    203.0.113.0/24 224.0.0.0/3
    ::/96 100::/64 2001:db8::/32 fc00::/7 fe80::/10 ff00::/8
);

# DNS64 synthesizes 64:ff9b:: addresses for public IPv4 hosts, so judge
# these by the IPv4 address they carry
my @EMBEDS_IPV4 = map { _network($_) } qw( ::ffff:0:0/96 64:ff9b::/96 );

sub post( $self, $args ) {
    my $uri = $args->{uri} or croak "missing uri";
    defined $args->{report} or croak "missing report";
    $uri = URI->new("$uri");

    my %headers = ( 'Content-Type' => 'application/gzip' );
    $headers{'Content-Disposition'} = qq{attachment; filename="$args->{filename}"}
        if $args->{filename};

    # 2013 draft 12.2.2: the request SHOULD carry the email Subject
    $headers{Subject} = $args->{subject} if $args->{subject};

    my %options = (
        headers       => \%headers,
        content       => $args->{report},
        data_callback => sub { },    # a success body is never read
    );
    if ( !$self->is_allowed_host( $uri->host ) ) {
        my ( $peer, $error ) = $self->public_peer( $uri->host );
        return _refused($error) if !$peer;
        $options{peer} = $peer;    # connect to the address that was checked
    }

    return $self->user_agent->post( "$uri", \%options );
}

sub is_allowed_host( $self, $host ) {
    my $allow = $self->config->{report_sending}{http_allow_hosts} or return 0;
    return scalar grep { lc $_ eq lc $host } split /[\s,]+/, $allow;
}

sub public_peer( $self, $host ) {
    my ( $error, @found ) = getaddrinfo( $host, undef, { socktype => SOCK_STREAM } );
    return ( undef, "unable to resolve $host: $error" ) if $error || !@found;

    my @addresses;
    for my $ai (@found) {
        my $packed
            = $ai->{family} == AF_INET6
            ? ( unpack_sockaddr_in6( $ai->{addr} ) )[1]
            : ( unpack_sockaddr_in( $ai->{addr} ) )[1];
        my $ip = inet_ntop( $ai->{family}, $packed );
        return ( undef, "$host resolves to non-public address $ip" )
            if !is_public_address($packed);
        push @addresses, $ip;
    }
    return $addresses[0];
}

sub is_public_address($packed) {
    if ( 16 == length $packed ) {
        for my $net (@EMBEDS_IPV4) {
            return is_public_address( substr $packed, 12 ) if _in_network( $packed, $net );
        }
    }
    return !grep { _in_network( $packed, $_ ) } @NON_PUBLIC;
}

sub user_agent($self) {
    return $self->{user_agent} //= HTTP::Tiny->new(
        agent        => "Mail-DMARC/$VERSION ",
        timeout      => 60,
        verify_SSL   => 1,
        max_redirect => 0,
        max_size     => $MAX_ERROR_BODY,
    );
}

sub _network($cidr) {
    my ( $ip, $bits ) = split m{/}, $cidr;
    my $prefix = inet_pton( $ip =~ /:/ ? AF_INET6 : AF_INET, $ip );
    my $mask   = pack 'B*', ( '1' x $bits ) . ( '0' x ( 8 * length($prefix) - $bits ) );
    return [ $prefix, $mask ];
}

sub _in_network( $packed, $net ) {
    my ( $prefix, $mask ) = @$net;
    return length $packed == length $prefix && ( $packed & $mask ) eq $prefix;
}

# shaped like HTTP::Tiny's own failures, so callers handle both alike
sub _refused($error) {
    return {
        success => '',
        status  => 599,
        reason  => 'Internal Exception',
        content => "$error\n",
        headers => {},
    };
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
verified and redirects are not followed.

A rua host that resolves to a loopback, private, link-local, shared,
documentation or multicast address is refused with a 599 response, and the
connection goes to the address that was checked. To deliver to an internal
endpoint on purpose, list its host in C<http_allow_hosts>:

  [report_sending]
  http_allow_hosts = dmarc.internal.example, 10.1.2.3

=head2 public_peer

Resolves a host and returns its first address, or C<(undef, $error)> when it
does not resolve or any of its addresses is not public.

=head2 is_public_address

True when a packed IPv4 or IPv6 address is globally routable.

=head2 is_allowed_host

True when the host is listed in C<report_sending.http_allow_hosts>.

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
