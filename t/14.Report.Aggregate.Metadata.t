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

my $mod = 'Mail::DMARC::Report::Aggregate';
use_ok($mod);
my $agg = $mod->new;
isa_ok( $agg, $mod );
my $meta = $agg->metadata;
isa_ok( $meta, 'Mail::DMARC::Report::Aggregate::Metadata' );

my $start = time;
my $end = time + 10;

my %scalar_accessors = (
    org_name           => 'Test Org',
    email              => 'test@example.com',
    extra_contact_info => 'http://www.example.com/path/to/dmarc.cgi',
    report_id          => '12345566677888@sender.com',
    uuid               => '1234908748913u41u4-1203847308924-adskfjadslfj-13i41230984',
);
for my $method ( sort keys %scalar_accessors ) {
    my $val = $scalar_accessors{$method};
    ok( $meta->$method($val), "$method, set" );
    cmp_ok( $meta->$method, 'eq', $val, "$method, get" );
}

test_date_range();
test_begin();
test_end();
test_error();
test_as_xml();

done_testing();
exit;

sub test_date_range  {
    my $range_ref = {begin=>$start,end=>$end};
    ok( $meta->date_range($range_ref), "date_range, set");
    is_deeply( $meta->date_range, $range_ref, "date_range, get");
    cmp_ok( $meta->begin, '==', $start, "date_range, get start");
    cmp_ok( $meta->end,   '==', $end,   "date_range, get end");
};
sub test_begin {
    ok( $meta->begin( $start ), "begin, set");
    cmp_ok( $meta->begin, '==', $start, "date_range, get start");
};
sub test_end {
    ok( $meta->end( $end ), "end, set");
    cmp_ok( $meta->end, '==', $end, "date_range, get end");
};
sub test_error {
    my $test_errors = [
        'error #1 for test',
        'error #2 for testing',
        ];
    foreach ( @$test_errors ) {
        ok( $meta->error( $_ ), "error, $_");
    };
    is_deeply($meta->error, $test_errors, "error, deeply");
};
sub test_as_xml  {
    my $expected = <<"EO_XML"
\t<report_metadata>
\t\t<org_name>Test Org</org_name>
\t\t<email>test\@example.com</email>
\t\t<extra_contact_info>http://www.example.com/path/to/dmarc.cgi</extra_contact_info>
\t\t<report_id>12345566677888\@sender.com</report_id>
\t\t<date_range>
\t\t\t<begin>$start</begin>
\t\t\t<end>$end</end>
\t\t</date_range>
\t\t<error>error #1 for test</error>
\t\t<error>error #2 for testing</error>
\t</report_metadata>
EO_XML
;
    chomp $expected;
    cmp_ok( $meta->as_xml, 'eq', $expected, "as_xml");
};

