use strict;
use warnings;

use Data::Dumper;
use Test::More;

use IO::Compress::Gzip;
use IO::Compress::Zip;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Receive';
use_ok( $mod );
my $recv = $mod->new;
isa_ok( $recv, $mod );

test_from_email_msg();

done_testing();
exit;

sub test_from_email_msg {
    ok( $recv->from_email_msg('report.msg'), 'from_email_msg');
};
