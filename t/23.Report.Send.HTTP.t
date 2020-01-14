use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

foreach my $req ( 'Net::HTTP' ) {
    eval "use $req";
    if ($@) {
        plan( skip_all => "$req not available" );
        exit;
    }
};

my $mod = 'Mail::DMARC::Report::Send::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

done_testing();
exit;

