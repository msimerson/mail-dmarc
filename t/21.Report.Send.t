use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Send';
use_ok($mod);
my $send = $mod->new;
isa_ok( $send,       $mod );
isa_ok( $send->smtp, 'Mail::DMARC::Report::Send::SMTP' );
isa_ok( $send->http, 'Mail::DMARC::Report::Send::HTTP' );

done_testing();
exit;

