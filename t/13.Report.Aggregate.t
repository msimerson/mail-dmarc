use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use Mail::DMARC::Policy;
use Mail::DMARC::Report::Aggregate::Record;

eval "use DBD::SQLite 1.31";
if ($@) {
    plan( skip_all => 'DBD::SQLite not available' );
    exit;
}

my $mod = 'Mail::DMARC::Report::Aggregate';
use_ok($mod);
my $agg = $mod->new;
isa_ok( $agg, $mod );

my $ip = '192.2.1.1';
my $test_r = Mail::DMARC::Report::Aggregate::Record->new(
    identifiers => {
        header_from   => 'example.com',
        envelope_from => 'example.com',
    },
    auth_results => { dkim => [ ], spf => [ ] },
    row => {
        source_ip => $ip,
        count     => 1,
        policy_evaluated => { disposition=>'none', dkim => 'pass', spf=>'pass' },
    },
);

test_metadata_isa();
test_record();
test_policy_published();
test_as_xml();

done_testing();
exit;

sub test_metadata_isa {
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
    is_deeply( $agg->record, [],"Mail::DMARC::Report::Aggregate::Record, empty");

    my $r;
    eval { $r = $agg->record( $test_r ) };
    ok( $r, "record, test") or diag Dumper($r);

    #delete $agg->record->[0]{config_file};
    is_deeply( $agg->record, [ $test_r ], "record, deeply");

    ok( $agg->record( $test_r ), "record, empty, again");
    #delete $agg->record->[1]{config_file};
    is_deeply( $agg->record, [ $test_r,$test_r ], "record, deeply, multiple");
};

sub test_as_xml {

    $agg->metadata->report_id(1);
    foreach my $m ( qw/ org_name email extra_contact_info error uuid / ) {
        $agg->metadata->$m("test");
    };
    foreach my $m ( qw/ begin end / ) {
        $agg->metadata->$m(time);
    };

    #$agg->record( $test_r );
    ok( $agg->metadata->as_xml(), "metadata, as_xml");
    ok( $agg->get_policy_published_as_xml(), "policy_published, as_xml");
    ok( $agg->get_record_as_xml(), "record, as_xml");
    ok( $agg->as_xml(), "as_xml");
};
