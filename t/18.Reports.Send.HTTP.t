use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Send::HTTP';
use_ok( $mod );
my $cli = $mod->new;
isa_ok( $cli, $mod );


done_testing();
exit;

