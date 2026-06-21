use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';

use Mail::DMARC;
use Mail::DMARC::Base;
use Mail::DMARC::Policy;
use Mail::DMARC::Result;
use Mail::DMARC::Result::Reason;
use Mail::DMARC::Report::Aggregate::Metadata;
use Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;
use Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
use Mail::DMARC::Report::Aggregate::Record::Identifiers;
use Mail::DMARC::Report::Aggregate::Record::Row;
use Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated;

sub clears_with_undef {
    my ($object, $method, $value) = @_;
    my $label = ref($object) . "::$method";
    $object->$method($value);
    is( $object->$method, $value, "$label stores initial value" );
    $object->$method(undef);
    ok( !defined $object->$method, "$label clears with explicit undef" );
}

sub croaks_with_undef {
    my ($object, $method, $value) = @_;
    my $label = ref($object) . "::$method";
    $object->$method($value);
    dies_ok { $object->$method(undef) } "$label treats explicit undef as a setter";
}

clears_with_undef( Mail::DMARC->new, 'local_policy', 'testing' );
croaks_with_undef( Mail::DMARC->new, 'source_ip', '192.0.2.1' );

clears_with_undef( Mail::DMARC::Base->new, 'verbose', 1 );

clears_with_undef( Mail::DMARC::Result::Reason->new, 'comment', 'note' );
croaks_with_undef( Mail::DMARC::Result::Reason->new, 'type', 'other' );

clears_with_undef( Mail::DMARC::Result->new, 'dkim_meta', 'meta' );
croaks_with_undef( Mail::DMARC::Result->new, 'result', 'pass' );

clears_with_undef( Mail::DMARC::Policy->new, 'domain', 'example.com' );
croaks_with_undef( Mail::DMARC::Policy->new, 'p', 'none' );

clears_with_undef( Mail::DMARC::Report::Aggregate::Record::Identifiers->new, 'header_from', 'example.com' );

clears_with_undef( Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated->new, 'dkim', 'pass' );
croaks_with_undef( Mail::DMARC::Report::Aggregate::Record::Row::Policy_Evaluated->new, 'disposition', 'none' );

clears_with_undef( Mail::DMARC::Report::Aggregate::Record::Row->new, 'count', 42 );

my $spf = Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new;
$spf->result('pass');
dies_ok { $spf->result(undef) } ref($spf) . "::result treats explicit undef as a setter";

my $dkim = Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(
    domain => 'example.com',
    result => 'pass',
);
clears_with_undef( $dkim, 'human_result', 'ok' );

my $metadata = Mail::DMARC::Report::Aggregate::Metadata->new;
clears_with_undef( $metadata, 'report_id', 'abc123' );
clears_with_undef( $metadata, 'begin', 123 );

done_testing();
