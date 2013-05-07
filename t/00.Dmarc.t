use strict;
use warnings;

use Test::More;

use lib 'lib';

use_ok( 'Mail::DMARC' );
use_ok( 'Mail::DMARC::PurePerl' );

my $dmarc = Mail::DMARC->new();
my $pp = Mail::DMARC::PurePerl->new();
isa_ok( $dmarc, 'Mail::DMARC' );
isa_ok( $pp, 'Mail::DMARC::PurePerl' );

my %sample_dmarc = (
        source_ip     => '192.0.1.1',
        envelope_to   => 'example.com',
        envelope_from => 'cars4you.info',
        header_from   => 'yahoo.com',
        dkim          => [ {
                domain      => 'example.com',
                selector    => 'apr2013',
                result      => 'fail',
                human_result=> 'fail (body has been altered)',
        } ],
        spf           => {
                domain => 'example.com',
                scope  => 'mfrom',
                result => 'pass',
        },
    );

test_new();
test_header_from();
test_setter_values();
test_spf();

done_testing();
exit;

sub test_spf {
    ok( $dmarc->spf( domain => 'a.c', scope=>'mfrom', result => 'fail' ), "spf");

    eval { $dmarc->spf( dom => 'foo', 'blah' ) };
    ok( $@, "spf, neg, $@");
};

sub test_header_from {

    my @good_vals = ( qw/ spam-example.com bar.com / );
    foreach my $k ( @good_vals ) {
        ok( $dmarc->header_from( $k ), "header_from, $k");
    };

    my @bad_vals = ( qw/ a.b a@b.c f*ct.org / );
    foreach my $k ( @bad_vals ) {
        eval { $dmarc->header_from( $k ); };
        chomp $@;
        ok( $@, "header_from, $k, $@" );
    };
};

sub test_setter_values {
    my %good_vals = (
            source_ip     => [ qw/ 0.0.0.0 1.1.1.1 255.255.255.255 / ],
            envelope_to   => [ qw/ example.com / ],
            envelope_from => [ qw/ example.com / ],
            header_from   => [ qw/ spam-example.com / ],
            dkim          => [ $sample_dmarc{dkim} ],
            spf           => [ $sample_dmarc{spf} ],
            );

    foreach my $k ( keys %good_vals ) {
        foreach my $t ( @{$good_vals{$k}} ) {
            ok( defined $dmarc->$k( $t ), "$k, $t");
        };
    };

    my %bad_vals = (
            source_ip     => [ qw/ 0.257.0.25 255.255.255.256 / ],
            envelope_to   => [ qw/ 3.a / ],
            envelope_from => [ qw/ / ],
            header_from   => [ qw/ / ],
            dkim          => [ qw/ / ],
            spf           => [ qw/ / ],
            );

    foreach my $k ( keys %bad_vals ) {
        foreach my $t ( @{$bad_vals{$k}} ) {
            eval { $dmarc->$k( $t ); };
            ok( $@, "neg, $k, $t");
        };
    };
};


sub test_new {
# empty policy
    my $dmarc = Mail::DMARC->new();
    isa_ok( $dmarc, 'Mail::DMARC' );
    is_deeply( $dmarc, {}, "new, empty" );

# new, one shot request
    $dmarc = Mail::DMARC->new( %sample_dmarc );
    isa_ok( $dmarc, 'Mail::DMARC' );
    is_deeply( $dmarc, \%sample_dmarc, "new, one shot" );

# new, individual accessors
    $dmarc = Mail::DMARC->new();
    isa_ok( $dmarc, 'Mail::DMARC' );
    foreach my $key ( keys %sample_dmarc ) {
        $dmarc->$key( $sample_dmarc{$key} );
    };
    delete $dmarc->{dns};
    is_deeply( $dmarc, \%sample_dmarc, "new, individual accessors" );
};

