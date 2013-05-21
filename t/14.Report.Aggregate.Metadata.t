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

test_org_name();
test_email();
test_extra_contact_info();
test_report_id();
test_date_range();
test_begin();
test_end();
test_error();
test_domain();
test_uuid();
test_as_xml();

done_testing();
exit;

sub test_org_name {
    my $name = 'Test Org';
    ok( $meta->org_name($name), "org_name, set");
    cmp_ok( $meta->org_name, 'eq', $name, "org_name, get");
};
sub test_email  {
    my $email = 'test@example.com';
    ok( $meta->email( $email ), "test_email, set");
    cmp_ok( $meta->email, 'eq', $email, "test_email, get");
};
sub test_extra_contact_info  {
    my $eci = 'http://www.example.com/path/to/dmarc.cgi';
    ok( $meta->extra_contact_info( $eci ), 'extra_contact_info, set');
    cmp_ok( $meta->extra_contact_info, 'eq', $eci, "extra_contact_info, get");
};
sub test_report_id  {
    my $id = '12345566677888@sender.com';
    ok( $meta->report_id($id), "report_id, set");
    cmp_ok( $meta->report_id, 'eq', $id, "report_id, get");
};
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
sub test_domain {
    my @domains = qw/ 3.am a.very.long.domain.with.subdomains /;
    foreach my $dom ( @domains ) {
        ok( $meta->domain( $dom ), "domain, set, $dom");
        cmp_ok( $meta->domain, 'eq', $dom, "domain, get, $dom" );
    };
};
sub test_uuid  {
    my $uuid = '1234908748913u41u4-1203847308924-adskfjadslfj-13i41230984';
    ok( $meta->uuid($uuid), "uuid, set");
    cmp_ok( $meta->uuid, 'eq', $uuid, "uuid, get");
};
sub test_as_xml  {
    my $expected = <<"EO_XML"
 <report_metadata>
  <report_id>12345566677888\@sender.com</report_id>
  <org_name>Test Org</org_name>
  <email>test\@example.com</email>
  <extra_contact_info>http://www.example.com/path/to/dmarc.cgi</extra_contact_info>
  <date_range>
   <begin>$start</begin>
   <end>$end</end>
  </date_range>
  <error>error #1 for test</error>
  <error>error #2 for testing</error>
 </report_metadata>
EO_XML
;
    chomp $expected;
    cmp_ok( $meta->as_xml, 'eq', $expected, "as_xml");
};

