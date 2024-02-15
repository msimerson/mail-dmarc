use strict;
use warnings;

use Data::Dumper;
use Net::DNS::Resolver::Mock;
use Test::Exception;
use Test::More;
use Test::File::ShareDir -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';
use Mail::DMARC::PurePerl;
use Mail::DMARC::Report;

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

eval "use XML::SAX::ParserFactory;";
if ($@) {
    plan( skip_all => 'XML::SAX::ParserFactory not available' );
    exit;
}

eval "use XML::Validator::Schema;";
if ($@) {
    plan( skip_all => 'XML::Validator::Schema not available' );
    exit;
}

my $resolver = new Net::DNS::Resolver::Mock();
$resolver->zonefile_parse(join("\n",
'tnpi.net.                         600 A   66.128.51.170',
'tnpi.net.                         600 MX  10 mail.theartfarm.com.',
'_dmarc.mail-dmarc.tnpi.net.       600 TXT "v=DMARC1; p=reject; rua=mailto:invalid@theartfarm.com; ruf=mailto:invalid@theartfarm.com; pct=90"',
'_dmarc.tnpi.net.                  600 TXT "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@theartfarm.com; ruf=mailto:dmarc-feedback@theartfarm.com; pct=100"',
'mail-dmarc.tnpi.net.              600 TXT "test zone for Mail::DMARC perl module"',
'mail-dmarc.tnpi.net._report._dmarc.theartfarm.com. 600 TXT "v=DMARC1; rua=mailto:invalid-test@theartfarm.com;"',
''));

my $dmarc = Mail::DMARC::PurePerl->new();
$dmarc->set_resolver($resolver);
my $store = $dmarc->report->store;

$store->config('t/mail-dmarc.ini');
$store->backend->config('t/mail-dmarc.ini');

die 'Not using test store' if $store->backend->config->{'report_store'}->{'dsn'} ne 'dbi:SQLite:dbname=t/reports-test.sqlite';

$dmarc->source_ip('66.128.51.165');
$dmarc->envelope_to('recipient.example.com');
$dmarc->envelope_from('dmarc-nonexist.tnpi.net');
$dmarc->header_from('mail-dmarc.tnpi.net');
$dmarc->dkim([
        {
        domain      => 'tnpi.net',
        selector    => 'jan2015',
        result      => 'fail',
        human_result=> 'fail (body has been altered)',
    }
]);
$dmarc->spf([
        {   domain => 'tnpi.net',
            scope  => 'mfrom',
            result => 'pass',
        },
        {
            scope  => 'helo',
            domain => 'mail.tnpi.net',
            result => 'fail',
        },
    ]);

my $policy = $dmarc->discover_policy;
my $result = $dmarc->validate($policy);

my $report_id = $dmarc->save_aggregate();
ok( $report_id, "saved report $report_id");

my $a = $store->backend->query('UPDATE report SET begin=begin-86400, end=end-86400 WHERE id=1');
   $a = $store->backend->query('INSERT INTO report_error(report_id,error,time) VALUES(1,"<ERROR> Test error & encoding",100)');

my $agg = $store->retrieve_todo()->[0];

test_against_schema();

done_testing();
exit;

sub test_against_schema {

    $agg->metadata->report_id(1);

    my $xml = $agg->as_xml();
    lives_ok( sub{
        my $validator = XML::Validator::Schema->new(file => 'share/rua-schema.xsd');
        my $parser = XML::SAX::ParserFactory->parser(Handler => $validator);
        $parser->parse_string( $xml );
    }, 'Check schema' );
    # print $xml;
}
