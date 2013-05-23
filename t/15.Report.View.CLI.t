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

my $mod = 'Mail::DMARC::Report::View::CLI';
use_ok($mod);
my $cli = $mod->new;
isa_ok( $cli, $mod );

$cli->store->backend->config('t/mail-dmarc.ini');

my $list = $cli->list();
ok( $list, "list, ".scalar @$list );

#warn Dumper($list);

done_testing();
exit;

