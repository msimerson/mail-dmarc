use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

my $mod = 'Mail::DMARC::Report::View::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

# this starts up the httpd daemon
#$http->dmarc_httpd();

done_testing();
exit;

