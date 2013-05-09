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

#warn Dumper($base);

done_testing();
exit;

