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

# negative config file test
$base = $mod->new( config_file => 'no such config' );
eval { $base->config };
chomp $@;
ok( $@, "invalid config file");

#warn Dumper($base);

done_testing();
exit;

