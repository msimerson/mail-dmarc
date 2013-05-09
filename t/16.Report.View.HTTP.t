use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::View::HTTP';
use_ok( $mod );
my $http = $mod->new;
isa_ok( $http, $mod );


done_testing();
exit;

