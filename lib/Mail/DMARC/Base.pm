package Mail::DMARC::Base;
use strict;
use warnings;

use Carp;
use Config::Tiny;
use File::ShareDir;
use IO::File;
use Net::DNS::Resolver;
use Net::IP;
use Regexp::Common 2013031301 qw /net/;
use Socket;
use Socket6 qw//;    # don't export symbols

sub new {
    my ( $class, @args ) = @_;
    croak "invalid args" if scalar @args % 2 != 0;
    return bless {
        config_file => 'mail-dmarc.ini',
        @args,       # this may override config_file
    }, $class;
}

sub config {
    my ( $self, $file, @too_many ) = @_;
    croak "invalid args" if scalar @too_many;
    return $self->{config} if ref $self->{config} && !$file;
    return $self->{config} = $self->get_config($file);
}

sub get_config {
    my $self = shift;
    my $file = shift || $self->{config_file} or croak;
    my @dirs = qw[ /usr/local/etc /opt/local/etc /etc ./ ];
    foreach my $d (@dirs) {
        next                              if !-d $d;
        next                              if !-e "$d/$file";
        croak "unreadable file: $d/$file" if !-r "$d/$file";
        my $Config = Config::Tiny->new;
        return Config::Tiny->read("$d/$file");
    }
    croak "unable to find config file $file\n";
}

sub any_inet_ntop {
    my ( $self, $ip_bin ) = @_;
    $ip_bin or croak "missing IP in request";

    if ( length $ip_bin == 16 ) {
        return Socket6::inet_ntop( AF_INET6, $ip_bin );
    }

    return Socket6::inet_ntop( AF_INET, $ip_bin );
}

sub any_inet_pton {
    my ( $self, $ip_txt ) = @_;
    $ip_txt or croak "missing IP in request";

    if ( $ip_txt =~ /:/ ) {
        return Socket6::inet_pton( AF_INET6, $ip_txt )
            or croak "invalid IPv6: $ip_txt";
    }

    return Socket6::inet_pton( AF_INET, $ip_txt )
        or croak "invalid IPv4: $ip_txt";
}

sub is_public_suffix {
    my ( $self, $zone ) = @_;

    croak "missing zone name!" if !$zone;

    my $file = $self->config->{dns}{public_suffix_list}
        || 'share/public_suffix_list';
    my @dirs = qw[ ./ /usr/local/ /opt/local /usr/ ];
    my $match;
    foreach my $dir (@dirs) {
        $match = $dir . $file;
        last if ( -f $match && -r $match );
    }
    if ( !-r $match ) {

        # Fallback to included suffic list, dies if not found/readable
        $match
            = File::ShareDir::dist_file( 'Mail-DMARC', 'public_suffix_list' );
    }

    my $fh = IO::File->new( $match, 'r' )
        or croak "unable to open $match for read: $!\n";

    $zone =~ s/\*/\\*/g;    # escape * char
    return 1 if grep {/^$zone$/} <$fh>;

    my @labels = split /\./, $zone;
    $zone = join '.', '\*', (@labels)[ 1 .. scalar(@labels) - 1 ];

    $fh = IO::File->new( $match, 'r' );    # reopen
    return 1 if grep {/^$zone$/} <$fh>;

    return 0;
}

sub has_dns_rr {
    my ( $self, $type, $domain ) = @_;

    my @matches;
    my $res     = $self->get_resolver();
    my $query   = $res->query( $domain, $type ) or do {
        return 0 if ! wantarray;
        return @matches;
    };
    for my $rr ( $query->answer ) {
        next if $rr->type ne $type;
        push @matches, $rr->type eq  'A'   ? $rr->address
                     : $rr->type eq 'PTR'  ? $rr->ptrdname
                     : $rr->type eq  'NS'  ? $rr->nsdname
                     : $rr->type eq  'TXT' ? $rr->txtdata
                     : $rr->type eq  'SPF' ? $rr->txtdata
                     : $rr->type eq 'AAAA' ? $rr->address
                     : $rr->type eq  'MX'  ? $rr->exchange
                     : $rr->answer;
    }
    return scalar @matches if ! wantarray;
    return @matches;
}

sub epoch_to_iso {
    my ($self, $epoch) = @_;

    my @fields = localtime( $epoch );

    my $ss = sprintf( "%02i", $fields[0] );    # seconds
    my $mn = sprintf( "%02i", $fields[1] );    # minutes
    my $hh = sprintf( "%02i", $fields[2] );    # hours (24 hour clock)

    my $dd = sprintf( "%02i", $fields[3] );        # day of month
    my $mm = sprintf( "%02i", $fields[4] + 1 );    # month
    my $yy = ( $fields[5] + 1900 );                # year

    return "$yy-$mm-$dd" .'T'."$hh:$mn:$ss";
};

sub get_resolver {
    my $self = shift;
    my $timeout = shift || $self->config->{dns}{timeout} || 5;
    return $self->{resolver} if defined $self->{resolver};
    $self->{resolver} = Net::DNS::Resolver->new( dnsrch => 0 );
    $self->{resolver}->tcp_timeout($timeout);
    $self->{resolver}->udp_timeout($timeout);
    return $self->{resolver};
}

sub is_valid_ip {
    my ( $self, $ip ) = @_;

    # Using Regexp::Common removes perl 5.8 compat
    # Perl 5.008009 does not support the pattern $RE{net}{IPv6}.
    # You need Perl 5.01 or later at lib/Mail/DMARC/DNS.pm line 83.

    if ( $ip =~ /:/ ) {
        return Net::IP->new( $ip, 6 );
    }

    return Net::IP->new( $ip, 4 );
}

sub is_valid_domain {
    my ( $self, $domain ) = @_;
    if ( $domain =~ /^$RE{net}{domain}{-rfc1101}{-nospace}$/x ) {
        my $tld = ( split /\./, $domain )[-1];
        return 1 if $self->is_public_suffix($tld);
        $tld = join( '.', ( split /\./, $domain )[ -2, -1 ] );
        return 1 if $self->is_public_suffix($tld);
    }
    return 0;
}

sub slurp {
    my ( $self, $file ) = @_;
    open my $FH, '<', $file or croak "unable to read $file: $!";
    my $contents = do { local $/; <$FH> };    ## no critic (Local)
    close $FH;
    return $contents;
}

sub verbose {
    return $_[0]->{verbose} if 1 == scalar @_;
    return $_[0]->{verbose} = $_[1];
};

1;

# ABSTRACT: DMARC utility functions
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
