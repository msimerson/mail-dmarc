use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Send::SMTP';
use_ok( $mod );
my $smtp = $mod->new;
isa_ok( $smtp, $mod );

done_testing(); exit;   # comment this out to spam yourself with 'make test'

$smtp->send(
        to      => 'admin@example.com',
        from    => 'do-not-reply@example.com',
        subject => 'Mail::DMARC::Report::Send::SMTP test',
        body    => 'This is a test. It is only a test',
        );

done_testing();
exit;

