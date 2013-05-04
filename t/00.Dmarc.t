use strict;
use warnings;

use Test::More;

use lib 'lib';

use_ok( 'Mail::DMARC' );
use_ok( 'Mail::DMARC::PurePerl' );

my $dmarc = Mail::DMARC->new();
my $pp = Mail::DMARC::PurePerl->new($dmarc);
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
test_setter_values();

done_testing();
exit;

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
    is_deeply( $dmarc, \%sample_dmarc, "new, individual accessors" );
};

