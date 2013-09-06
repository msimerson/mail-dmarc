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

my $body = $send->too_big_report(
            {   uri          => 'mailto:matt@example.com',
                report_bytes => 500000,
                report_id    => 1,
                report_domain=> 'destination.com',
            }
        );

ok( $body, 'too_big_report');
#cmp_ok( $body, 'eq', sample_too_big(), 'too_big_report: content');

done_testing();
exit;

sub sample_too_big {
    return <<'EO_TOO_BIG'
This is a \'too big\' DMARC notice. The aggregate report was NOT delivered.

Report-Date: Wed, 14 Aug 2013 22:15:04 -0700
Report-Domain: destination.com
Report-ID: 1
Report-Size: 500000
Submitter: example.com
Submitting-URI: mailto:matt@example.com

Submitted by My Great Company
Generated with Mail::DMARC

EO_TOO_BIG
;
};
