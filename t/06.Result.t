use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::Result' );

my $result = Mail::DMARC::Result->new;

isa_ok( $result, 'Mail::DMARC::Result' );

test_published();
test_evaluated();

done_testing();
exit;

sub test_published {

    $result->published();
};

sub test_evaluated {

    $result->evaluated();
};
