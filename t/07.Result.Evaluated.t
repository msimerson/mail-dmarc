use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';
use_ok( 'Mail::DMARC::Result::Evaluated' );

my $e = Mail::DMARC::Result::Evaluated->new;
isa_ok( $e, 'Mail::DMARC::Result::Evaluated' );

test_disposition();
test_dkim();
test_dkim_align();
test_spf();
test_result();
test_reason();
test_dkim_meta();

done_testing();
exit;

sub test_disposition {
# positive tests
    foreach (qw/ none reject quarantine NONE REJECT QUARANTINE /) {
        ok( $e->disposition($_), "disposition, $_")
    };

# negative tests
    foreach (qw/ non rejec quarantin NON REJEC QUARANTIN /) {
        eval { $e->disposition($_) };
        chomp $@;
        ok( $@, "disposition, neg, $_, $@")
    };
}

sub test_dkim {
    test_pass_fail('dkim');
}

sub test_dkim_align{
    strict_relaxed('dkim_align');
};

sub test_dkim_meta {
    ok( $e->dkim_meta( { domain => 'test' } ), "dkim_meta");
}

sub test_spf {
    test_pass_fail('spf');
}

sub test_spf_align {
    strict_relaxed('spf_align');
}

sub test_reason{
# positive tests
    foreach (qw/ forwarded sampled_out trusted_forwarder mailing_list local_policy other /) {
        ok( $e->reason->type( $_ ), "reason type: $_");
        ok( $e->reason->comment('test'), "reason comment");
    };

# negative tests
    foreach (qw/ any reason not in above list /) {
        eval { $e->reason->type( $_ ) };
        chomp $@;
        ok( $@, "reason, $_, $@");
    };
}

sub test_result {
    test_pass_fail('result');
}

sub test_pass_fail {
    my $sub = shift;

# positive tests
    foreach (qw/ pass fail PASS FAIL /) {
        ok( $e->$sub($_), "$sub, $_")
    };

# negative tests
    foreach (qw/ pas fai PAS FAI /) {
        eval { $e->$sub($_) };
        chomp $@;
        ok( $@, "$sub, neg, $_, $@")
    };
};

sub strict_relaxed {
    my $sub = shift;
# positive tests
    foreach (qw/ strict relaxed STRICT RELAXED /) {
        ok( $e->$sub($_), "$sub, $_")
    };

# negative tests
    foreach (qw/ stric relaxe STRIC RELAXE /) {
        eval { $e->$sub($_) };
        chomp $@;
        ok( $@, "$sub, neg, $_, $@")
    };
}

