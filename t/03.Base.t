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

#warn Dumper($base);

done_testing();
exit;

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
            $pres =~ s/::/:0:/g;
            cmp_ok( $pres, 'eq', $ip, "inet_ntop, $ip");
        };
    };
};
