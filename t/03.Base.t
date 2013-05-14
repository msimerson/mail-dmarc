use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Base';
use_ok( $mod );
my $base = $mod->new;
isa_ok( $base, $mod );
isa_ok( $base->config, 'Config::Tiny' );
isa_ok( $base->get_resolver(), 'Net::DNS::Resolver' );

# invalid config file
$base = $mod->new( config_file => 'no such config' );
eval { $base->config };
chomp $@;
ok( $@, "invalid config file");

# alternate config file
$base = $mod->new();
eval { $base->config('t/mail-dmarc.ini'); };
chomp $@;
ok( ! $@, "alternate config file");

test_inet_to();
test_is_public_suffix();
test_has_dns_rr();
test_is_valid_ip();
test_is_valid_domain();

done_testing();
exit;
#warn Dumper($base);

sub test_inet_to {

    my @test_ips = (
            '1.1.1.1',
            '10.0.1.1',
            '2002:4c79:6240::1610:9fff:fee5:fb5',
            '2607:f060:b008:feed::6',
            );

    foreach my $ip ( @test_ips ) {
        my $bin = $base->inet_pton( $ip );
        ok( $bin, "inet_pton, $ip");
        my $pres = $base->inet_ntop( $bin );
        ok( $pres, "inet_ntop, $ip");
        if ( $pres eq $ip ) {
            cmp_ok( $pres, 'eq', $ip, "inet_ntop, $ip");
        }
        else {
# on some linux systems, a :: pattern gets a zero inserted.
            my $zero_filled = $ip;
            $zero_filled =~ s/::/:0:/g;
            cmp_ok( $pres, 'eq', $zero_filled, "inet_ntop, $ip") 
                or diag "presentation: $zero_filled\nresult: $pres";
        };
    };
};

sub test_is_valid_ip {
# positive tests
    foreach ( qw/ 0.0.0.0 1.1.1.1 255.255.255.255 2607:f060:b008:feed::2 / ) {
        ok( $base->is_valid_ip($_), "is_valid_ip, $_");
    };

# negative tests
    foreach ( qw/ 256.1.1.1 a 1.1.1.256 / ) {
        ok( ! $base->is_valid_ip($_), "is_valid_ip, neg, $_");
    };
};

sub test_is_valid_domain {

# positive tests
    foreach ( qw/ example.com bbc.co.uk 3.am / ) {
        ok( $base->is_valid_domain($_), "is_valid_domain, $_");
    };

# negative tests
    foreach ( qw/ example.m bbc.co.k 3.a / ) {
        ok( ! $base->is_valid_domain($_), "is_valid_domain, $_");
    };

};

sub test_has_dns_rr {

    my %tests = (
        'NS:tnpi.net'                 => 1,
        'NS:fake.mail-dmarc.tnpi.net' => 0,
        'A:www.tnpi.net'              => 1,
        'MX:tnpi.net'                 => 1,
        'MX:gmail.com'                => 1,
    );

    foreach my $dom ( keys %tests ) {
        my $r = $base->has_dns_rr( split /:/, $dom  );
# no need to raise test errors for CPAN test systems with unreliable DNS
        next if ! $r && $tests{$dom};
        ok( $r >= $tests{$dom}, "has_dns_rr, $dom" );
    }
};

sub test_is_public_suffix {
    my %tests = (
            'www.tnpi.net' => 0,
            'tnpi.net'     => 0,
            'net'          => 1,
            'com'          => 1,
            'co.uk'        => 1,
            '*.uk'         => 1,
            'google.com'   => 0,
            'a'            => 0,
            'z'            => 0,
            );

    foreach my $dom ( keys %tests ) {
        my $t = $tests{$dom} == 0 ? 'neg' : 'pos';
        cmp_ok( $tests{$dom}, '==', $base->is_public_suffix( $dom ), "is_public_suffix, $t, $dom" );
    };
};

