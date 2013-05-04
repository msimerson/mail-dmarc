package Mail::DMARC::DNS;
# ABSTRACT: DNS functions for DMARC

use strict;
use warnings;

use Carp;
use IO::File;
use Net::DNS::Resolver;
use Regexp::Common qw /net/;

use lib 'lib';

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
    if ( $ip =~ /:/ ) {
        return 1 if $ip =~ /^$RE{net}{IPv6}$/;
        return 0;
    };

    return 1 if $ip =~ /^$RE{net}{IPv4}$/;
    return 0;
};

sub is_valid_domain {
    my ($self, $domain) = @_;
    if ( $domain =~ /^$RE{net}{domain}{-rfc1101}{-nospace}$/ ) {
        my $tld = (split /\./,$domain)[-1];
#warn "tld: $tld\n";
        return 1 if Mail::DMARC::DNS::is_public_suffix(undef,$tld);
        $tld = join('.', (split /\./,$domain)[-2,-1] );
#warn "tld: $tld\n";
        return 1 if Mail::DMARC::DNS::is_public_suffix(undef,$tld);
    };
    return 0;
};

1;
