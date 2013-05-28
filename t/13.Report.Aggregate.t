use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use Mail::DMARC::Policy;

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

my $mod = 'Mail::DMARC::Report::Aggregate';
use_ok($mod);
my $agg = $mod->new;
isa_ok( $agg, $mod );

test_metadata();
test_policy_published();
test_record();
test_as_xml();

done_testing();
exit;

sub test_metadata {
    isa_ok( $agg->metadata, "Mail::DMARC::Report::Aggregate::Metadata");
};

sub test_policy_published {
    ok( ! defined $agg->policy_published, "policy_published, empty" );
    my $pol = Mail::DMARC::Policy->new();
    $pol->apply_defaults;
    $pol->domain('test.com');
    ok( $agg->policy_published($pol), "policy_published, default" );
}

sub test_record {
    my $ip = '192.2.1.1';
    my $test_r = { source_ip => $ip, policy_evaluated => { disposition=>'pass', dkim => 'pass', spf=>'pass' } };
    ok( $agg->record( $test_r ), "record, empty");
    is_deeply( $agg->record, [ $test_r ], "record, deeply");
    $agg->record( $test_r, "record, empty, again");
    is_deeply( $agg->record, [ $test_r,$test_r ], "record, deeply, multiple");
};

sub test_as_xml {

    $agg->metadata->report_id(1);
    foreach my $m ( qw/ org_name email extra_contact_info error domain uuid / ) {
        $agg->metadata->$m("test");
    };
    foreach my $m ( qw/ begin end / ) {
        $agg->metadata->$m(time);
    };

    ok( $agg->as_xml(), "as_xml");
};
