use strict;
use warnings;

use Test::More;

use lib 'lib';

use_ok('Mail::DMARC');

my $dmarc = Mail::DMARC->new();
isa_ok( $dmarc, 'Mail::DMARC' );

my %sample_dmarc = (
    config_file   => 'mail-dmarc.ini',
    source_ip     => '192.0.1.1',
    envelope_to   => 'example.com',
    envelope_from => 'cars4you.info',
    header_from   => 'yahoo.com',
    dkim          => [
        {   domain       => 'example.com',
            selector     => 'apr2013',
            result       => 'fail',
            human_result => 'fail (body has been altered)',
        }
    ],
    spf => [
        {   domain => 'example.com',
            scope  => 'mfrom',
            result => 'pass',
        }
    ],
);

test_new();
test_header_from();
test_setter_values();
test_spf();
test_dkim();

done_testing();
exit;

sub test_dkim {
# set DKIM with key=>val pairs
    $dmarc->{dkim} = undef;
    my %test_dkim = ( domain => 'a.c', result => 'fail' );
    ok( $dmarc->dkim(%test_dkim), "dkim, hash set" );
    is_deeply($dmarc->dkim, [ \%test_dkim ], "dkim, hash set result");

# set with a hashref
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim(\%test_dkim), "dkim, hashref set" );
    is_deeply($dmarc->dkim, [ \%test_dkim ], "dkim, hashref set, result");

# set with an arrayref
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim([ \%test_dkim ]), "dkim, arrayref set" );
    is_deeply($dmarc->dkim, [ \%test_dkim ], "dkim, arrayref set result");

# set with arrayref, two values
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim([ \%test_dkim, \%test_dkim ]), "dkim, arrayref set" );
    is_deeply($dmarc->dkim, [ \%test_dkim, \%test_dkim ], "dkim, arrayref set result");

# set DKIM with invalid key=>val pairs
    eval { $dmarc->dkim( dom => 'foo', 'blah' ) };
    chomp $@;
    ok( $@, "dkim, neg, $@" );

    eval { $dmarc->dkim( { domain => 'foo.com', result => 'non-existent' } ) };
    chomp $@;
    ok( $@, "dkim, neg, $@" );
}

sub test_spf {
# set SPF with key=>val pairs
    $dmarc->{spf} = undef;
    my %test_spf = ( domain => 'a.c', scope => 'mfrom', result => 'fail' );
    ok( $dmarc->spf(%test_spf), "spf, hash set" );
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, hash set result");

# set with a hashref
    $dmarc->{spf} = undef;
    ok( $dmarc->spf(\%test_spf), "spf, hashref set" );
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, hashref set, result");

# set with an arrayref
    $dmarc->{spf} = undef;
    ok( $dmarc->spf([ \%test_spf ]), "spf, arrayref set" );
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, arrayref set result");

# set with arrayref, two values
    $dmarc->{spf} = undef;
    ok( $dmarc->spf([ \%test_spf, \%test_spf ]), "spf, arrayref set" );
    is_deeply($dmarc->spf, [ \%test_spf, \%test_spf ], "spf, arrayref set result");

# set SPF with invalid key=>val pairs
    eval { $dmarc->spf( dom => 'foo', 'blah' ) };
    chomp $@;
    ok( $@, "spf, neg, $@" );
}

sub test_header_from {

    my @good_vals = (qw/ spam-example.com bar.com /);
    foreach my $k (@good_vals) {
        ok( $dmarc->header_from($k), "header_from, $k" );
    }

    my @bad_vals = (qw/ a.b a@b.c f*ct.org /);
    foreach my $k (@bad_vals) {
        eval { $dmarc->header_from($k); };
        chomp $@;
        ok( $@, "header_from, $k, $@" );
    }
}

sub test_setter_values {
    my %good_vals = (
        source_ip     => [qw/ 0.0.0.0 1.1.1.1 255.255.255.255 /],
        envelope_to   => [qw/ example.com /],
        envelope_from => [qw/ example.com /],
        header_from   => [qw/ spam-example.com /],
        dkim          => [ $sample_dmarc{dkim} ],
        spf           => [ $sample_dmarc{spf} ],
    );

    foreach my $k ( keys %good_vals ) {
        foreach my $t ( @{ $good_vals{$k} } ) {
            ok( defined $dmarc->$k($t), "$k, $t" );
        }
    }

    my %bad_vals = (
        source_ip     => [qw/ 0.257.0.25 255.255.255.256 /],
        envelope_to   => [qw/ 3.a /],
        envelope_from => [qw/ /],
        header_from   => [qw/ /],
        dkim          => [qw/ /],
        spf           => [qw/ /],
    );

    foreach my $k ( keys %bad_vals ) {
        foreach my $t ( @{ $bad_vals{$k} } ) {
            eval { $dmarc->$k($t); };
            ok( $@, "neg, $k, $t" ) or diag $dmarc->$k($t);
        }
    }
}

sub test_new {

    # empty policy
    my $dmarc = Mail::DMARC->new();
    isa_ok( $dmarc, 'Mail::DMARC' );
    is_deeply( $dmarc, { config_file => 'mail-dmarc.ini' }, "new, empty" );

    # new, one shot request
    $dmarc = Mail::DMARC->new(%sample_dmarc);
    isa_ok( $dmarc, 'Mail::DMARC' );
    is_deeply( $dmarc, \%sample_dmarc, "new, one shot" );

    # new, individual accessors
    $dmarc = Mail::DMARC->new();
    isa_ok( $dmarc, 'Mail::DMARC' );
    foreach my $key ( keys %sample_dmarc ) {
        next if grep {/$key/} qw/ config config_file /;
        eval { $dmarc->$key( $sample_dmarc{$key} ); }
            or diag "error running $key with $sample_dmarc{$key} arg: $@";
    }
    delete $dmarc->{config};
    is_deeply( $dmarc, \%sample_dmarc, "new, individual accessors" );
}

