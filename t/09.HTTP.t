use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

foreach my $req ( 'DBD::SQLite 1.31', 'Net::Server::HTTP' ) {
    eval "use $req";
    if ($@) {
        plan( skip_all => "$req not available" );
        exit;
    }
};

my $mod = 'Mail::DMARC::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

# this starts up the httpd daemon
#$http->dmarc_httpd();

done_testing();
exit;

