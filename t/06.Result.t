use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::PurePerl' );
use_ok( 'Mail::DMARC::Result' );
use_ok( 'Mail::DMARC::Result::Evaluated' );

my $pp = Mail::DMARC::PurePerl->new;
my $result = Mail::DMARC::Result->new;

isa_ok( $result, 'Mail::DMARC::Result' );

test_published();
test_evaluated();

done_testing();
exit;

sub test_published {

    $pp->header_from('tnpi.net');
    $pp->dkim([{ domain => 'tnpi.net', result=>'pass' }]);
    $pp->spf({ domain => 'tnpi.net', result=>'pass' });

    ok( $pp->validate(), "validate");
    ok( $pp->result->published(), "published");
};

sub test_evaluated {

    ok( $result->evaluated(), "evaluated");
};
