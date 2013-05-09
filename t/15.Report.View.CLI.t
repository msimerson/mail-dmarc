use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::View::CLI';
use_ok( $mod );
my $cli = $mod->new;
isa_ok( $cli, $mod );

$cli->store->backend->config('t/mail-dmarc.ini');

ok( $cli->list(), "list");

done_testing();
exit;

