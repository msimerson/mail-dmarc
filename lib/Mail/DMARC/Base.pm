package Mail::DMARC::Base;
our $VERSION = '1.20260226';
use strict;
use warnings;
use 5.10.0;

use Carp;
use Config::Tiny;
use File::ShareDir;
use HTTP::Tiny;
use IO::File;
use Net::DNS::Resolver;
use Net::IDN::Encode qw/domain_to_unicode/;
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

my $_fake_time;
sub time { ## no critic
    # Ability to return a fake time for testing
    my ( $self ) = @_;
    my $time = defined $Mail::DMARC::Base::_fake_time ? $Mail::DMARC::Base::_fake_time : time;
    return $time;
}
sub set_fake_time {
    my ( $self, $time ) = @_;
    $Mail::DMARC::Base::_fake_time = $time;
    return;
}

sub config {
    my ( $self, $file, @too_many ) = @_;
    croak "invalid args" if scalar @too_many;
    return $self->{config} if ref $self->{config} && !$file;
    return $self->{config} = $self->get_config($file);
}

sub get_prefix {
    my ($self, $subdir) = @_;
    return map { $_ . ($subdir ? $subdir : '') } qw[ /usr/local/ /opt/local/ / ./ ];
}

sub get_sharefile {
    my ($self, $file) = @_;

    my $match = File::ShareDir::dist_file( 'Mail-DMARC', $file );
    print "using $match for $file\n" if $self->verbose;
    return $match;
}

sub get_config {
    my $self = shift;
    my $file = shift || $ENV{MAIL_DMARC_CONFIG_FILE} || $self->{config_file} or croak;
    return Config::Tiny->read($file) if -r $file;  # fully qualified
    foreach my $d ($self->get_prefix('etc')) {
        next                              if !-d $d;
        next                              if !-e "$d/$file";
        croak "unreadable file: $d/$file" if !-r "$d/$file";
        my $Config = Config::Tiny->new;
        return Config::Tiny->read("$d/$file");
    }

    if ($file ne 'mail-dmarc.ini') {
        croak "unable to find requested config file $file\n";
    }
    return Config::Tiny->read( $self->get_sharefile('mail-dmarc.ini') );
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
            || croak "invalid IPv6: $ip_txt";
    }

    return Socket6::inet_pton( AF_INET, $ip_txt )
        || croak "invalid IPv4: $ip_txt";
}

{
    my $public_suffixes;
    my $public_suffixes_stamp;

    sub get_public_suffix_list {
        my ( $self ) = @_;
        if ( $public_suffixes ) { return $public_suffixes; }
        no warnings 'once';  ## no critic
        $Mail::DMARC::psl_loads++;
        my $file = $self->find_psl_file();
        $public_suffixes_stamp = ( stat( $file ) )[9];

        open my $fh, '<:encoding(UTF-8)', $file
            or croak "unable to open $file for read: $!\n";
        # load PSL into hash for fast lookups, esp. for long running daemons
        my %psl = map { $_ => 1 }
                  grep { $_ !~ /^[\/\s]/ } # weed out comments & whitespace
                  map { chomp($_); $_ }    ## no critic, remove line endings
                  <$fh>;
        close $fh;
        return $public_suffixes = \%psl;
    }

    sub check_public_suffix_list {
        my ( $self ) = @_;
        my $file = $self->find_psl_file();
        my $new_public_suffixes_stamp = ( stat( $file ) )[9];
        if ( $new_public_suffixes_stamp != $public_suffixes_stamp ) {
            $public_suffixes = undef;
            $self->get_public_suffix_list();
            return 1;
        }
        return 0;
     }
 }

sub is_public_suffix {
    my ( $self, $zone ) = @_;

    croak "missing zone name!" if !$zone;

    my $public_suffixes = $self->get_public_suffix_list();

    $zone = domain_to_unicode( $zone ) if $zone =~ /xn--/;

    return 1 if $public_suffixes->{$zone};

    my @labels = split /\./, $zone;
    $zone = join '.', '*', (@labels)[ 1 .. scalar(@labels) - 1 ];

    return 1 if $public_suffixes->{$zone};
    return 0;
}

sub update_psl_file {
    my ($self, $dryrun) = @_;

    my $psl_file = $self->find_psl_file();

    die "No Public Suffix List file found\n"                  if ( ! $psl_file );
    die "Public suffix list file $psl_file not found\n"       if ( ! -f $psl_file );
    die "Cannot write to Public Suffix List file $psl_file\n" if ( ! -w $psl_file );

    my $url = 'https://publicsuffix.org/list/effective_tld_names.dat';
    if ( $dryrun ) {
        print "Will attempt to update the Public Suffix List file at $psl_file (dryrun mode)\n";
        return;
    }

    my $response = HTTP::Tiny->new->mirror( $url, $psl_file );
    my $content = $response->{'content'};
    if ( !$response->{'success'} ) {
        my $status = $response->{'status'};
        die "HTTP Request for Public Suffix List file failed with error $status ($content)\n";
    }
    else {
        if ( $response->{'status'} eq '304' ) {
            print "Public Suffix List file $psl_file not modified\n";
        }
        else {
            print "Public Suffix List file $psl_file updated\n";
        }
    }
    return;
}

sub find_psl_file {
    my ($self) = @_;

    my $file = $self->config->{dns}{public_suffix_list} || 'share/public_suffix_list';
    if ( $file =~ /^\// && -f $file && -r $file ) {
        print "using $file for Public Suffix List\n" if $self->verbose;
        return $file;
    }

    foreach my $path ($self->get_prefix($file)) {
        if ( -f $path && -r $path ) {
            print "using $path for Public Suffix List\n"; # if $self->verbose;
            return $path;
        }
    }

    # Fallback to included suffic list
    return $self->get_sharefile('public_suffix_list');
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
}

sub get_resolver {
    my $self = shift;
    my $timeout = shift || $self->config->{dns}{timeout} || 5;
    my $retrans = shift || $self->config->{dns}{retrans} || 5;
    return $self->{resolver} if defined $self->{resolver};
    $self->{resolver} = Net::DNS::Resolver->new( dnsrch => 0 );
    $self->{resolver}->tcp_timeout($timeout);
    $self->{resolver}->udp_timeout($timeout);
    $self->{resolver}->retrans($retrans);
    return $self->{resolver};
}

sub set_resolver {
    my ($self,$resolver) = @_;
    $self->{resolver} = $resolver;
    return;
}

sub is_valid_ip {
    my ( $self, $ip ) = @_;

    # Using Regexp::Common removes perl 5.8 compat
    # Perl 5.008009 does not support the pattern $RE{net}{IPv6}.
    # You need Perl 5.01 or later

    if ( $ip =~ /:/ ) {
        return Net::IP->new( $ip, 6 );
    }

    return Net::IP->new( $ip, 4 );
}

sub is_valid_domain {
    my ( $self, $domain ) = @_;
    return 0 if $domain !~ /^$RE{net}{domain}{-rfc1101}{-nospace}$/x;
    my $tld = ( split /\./, $domain )[-1];
    return 1 if $self->is_public_suffix($tld);
    return 0 if $domain eq 'localhost';
    return 0 if $tld eq 'localdomain';
    $tld = join( '.', ( split /\./, $domain )[ -2, -1 ] );
    return 1 if $self->is_public_suffix($tld);
    return 0;
}

sub is_valid_spf_scope {
    my ($self, $scope ) = @_;
    return lc $scope if grep { lc $scope eq $_ } qw/ mfrom helo /;
    carp "$scope is not a valid SPF scope";
    return;
}

sub is_valid_spf_result {
    my ($self, $result ) = @_;
    return 1 if grep { lc $result eq $_ }
        qw/ fail neutral none pass permerror softfail temperror /;
    carp "$result is not a valid SPF result";
    return;
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
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Base - DMARC utility functions

=head1 VERSION

version 1.20260226

=head1 METHODS

=head2 is_public_suffix

Determines if part of a domain is a Top Level Domain (TLD). Examples of TLDs are com, net, org, co.ok, am, and us.

Determination is made by consulting a Public Suffix List. The included PSL is from mozilla.org. See http://publicsuffix.org/list/ for more information, and a link to download the latest PSL.

=head2 update_psl_file

Download a new Public Suffix List file from mozilla and update the installed file with the new copy.

=head2 has_dns_rr

Determine if a DNS Resource Record of the specified type exists at the DNS name provided.

=head2 get_resolver

Returns a (cached) Net::DNS::Resolver object

=head2 set_resolver

Set the Net::DNS::Resolver object to be used for lookups

=head2 is_valid_ip

Determines if the supplied IP address is a valid IPv4 or IPv6 address.

=head2 is_valid_domain

Determine if a string is a legal RFC 1034 or 1101 host name.

Half the reason to test for domain validity is to shave seconds off our processing time by not having to process DNS queries for illegal host names. The other half is to raise exceptions if methods are being called incorrectly.

=head1 SEE ALSO

Mozilla Public Suffix List: http://publicsuffix.org/list/

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

