package Mail::DMARC::DNS;

use strict;
use warnings;

use Carp;
use IO::File;
use Net::DNS::Resolver;
use Net::IP;
use Regexp::Common qw /net/;

sub new {
    my $class = shift;
    return bless {
        dns_timeout   => 5,
        resolver      => undef,
        ps_file       => 'share/public_suffix_list',
    },
    $class;
}

sub is_public_suffix {
    my ($self, $zone) = @_;

    croak "missing zone name!" if ! $zone;

    my $file = $self->{ps_file} || 'share/public_suffix_list';
    my @dirs = qw[ ./ /usr/local/ /usr/ /opt/local ];
    my $match;
    foreach my $dir ( @dirs ) {
        $match = $dir . $file;
        last if ( -f $match && -r $match );
    };
    if ( ! -r $match ) {
        croak "unable to locate readable public suffix file\n";
    };

    my $fh = IO::File->new( $match, 'r' )
        or croak "unable to open $match for read: $!\n";

    $zone =~ s/\*/\\*/g;   # escape * char
    return 1 if grep {/^$zone$/} <$fh>;

    my @labels = split /\./, $zone;
    $zone = join '.', '\*', (@labels)[1 .. scalar(@labels) - 1];

    $fh = IO::File->new( $match, 'r' );  # reopen
    return 1 if grep {/^$zone$/} <$fh>;

    return 0;
};

sub has_dns_rr {
    my ($self, $type, $domain) = @_;

    my $matches = 0;
    my $res = $self->get_resolver();
    my $query = $res->query($domain, $type) or return $matches;
    for my $rr ($query->answer) {
        next if $rr->type ne $type;
        $matches++;
    }
    return $matches;
};

sub get_resolver {
    my $self = shift;
    my $timeout = shift || $self->{dns_timeout} || 5;
    return $self->{resolver} if defined $self->{resolver};
    $self->{resolver} = Net::DNS::Resolver->new(dnsrch => 0);
    $self->{resolver}->tcp_timeout($timeout);
    $self->{resolver}->udp_timeout($timeout);
    return $self->{resolver};
}

sub is_valid_ip {
    my ($self, $ip) = @_;

# Using Regexp::Common removes perl 5.8 compat
# Perl 5.008009 does not support the pattern $RE{net}{IPv6}.
# You need Perl 5.01 or later at lib/Mail/DMARC/DNS.pm line 83.

    if ( $ip =~ /:/ ) {
        return Net::IP->new( $ip, 6 );
    };

    return Net::IP->new( $ip, 4 );
};

sub is_valid_domain {
    my ($self, $domain) = @_;
    if ( $domain =~ /^$RE{net}{domain}{-rfc1101}{-nospace}$/x ) {
        my $tld = (split /\./,$domain)[-1];
        return 1 if $self->is_public_suffix($tld);
        $tld = join('.', (split /\./,$domain)[-2,-1] );
        return 1 if $self->is_public_suffix($tld);
    };
    return 0;
};

1;
# ABSTRACT: DNS functions for DMARC
__END__
sub {}

=head1 METHODS

=head2 is_public_suffix

Determines if part of a domain is a Top Level Domain (TLD). Examples of TLDs are com, net, org, co.ok, am, and us.

Determination is made by consulting a Public Suffix List. The included PSL is from mozilla.org. See http://publicsuffix.org/list/ for more information, and a link to download the latest PSL.

The authors of this module anticipate adding a function to this class which will periodically update the PSL.

=head2 has_dns_rr

Determine if a DNS Resource Record of the specified type exists at the DNS name provided.

=head2 get_resolver

Returns a (cached) Net::DNS::Resolver object

=head2 is_valid_ip

Determines if the supplied IP address is a valid IPv4 or IPv6 address.

=head2 is_valid_domain

Determine if a string is a legal RFC 1034 or 1101 host name.

Half the reason to test for domain validity is to shave seconds off our processing time by not having to process DNS queries for illegal host names. The other half is to raise exceptions if methods are being called incorrectly.

=head1 SEE ALSO

Mozilla Public Suffix List: http://publicsuffix.org/list/

=cut
