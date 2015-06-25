use strict;
use warnings;

use Data::Dumper;
use Test::More;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

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
            selector     => 'apr2015',
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
test_config_file_first();
test_header_from();
test_setter_values();
test_spf();
test_dkim();
test_zulu_time();
test_report_window();
test_interval_limits();
test_public_suffix_list();

done_testing();
exit;

sub test_public_suffix_list {

    my $data = {
        'com'                    => 1,
        'examplebogusdomainname' => 0,
        'xn--55qx5d.cn'          => 1,
        'xn--zfr164b'            => 1,
    };

    foreach my $domain ( keys %$data ) {
        my $result = $dmarc->is_public_suffix( $domain );
        is( $result, $data->{ $domain }, "Public Suffix: $domain" );
    }

}

sub test_zulu_time {

    my $data = [
        [ 'Day Start'  , 1426032000, 1426032000 ],
        [ 'Day Middle' , 1426032050, 1426032000 ],
        [ 'Day End'    , 1426118399, 1426032000 ],
        [ 'Day Next'   , 1426118400, 1426118400 ],
    ];

    foreach my $test ( @$data ) {
        my ( $name, $now, $begin ) = @$test;
        my $c_begin = $dmarc->get_start_of_zulu_day( $now );
        is( $c_begin, $begin, "Zulu Day: $name" ); 
    }

}

sub test_report_window {

    my $data = [
        [ 'Daily Start'          , 86400, 1426032000, 1426032000, 1426118399 ],
        [ 'Daily Middle'         , 86400, 1426032050, 1426032000, 1426118399 ],
        [ 'Daily End'            , 86400, 1426118399, 1426032000, 1426118399 ],
        [ 'Hourly First Start'   , 3600,  1426032000, 1426032000, 1426035599 ],
        [ 'Hourly First Middle'  , 3600,  1426032050, 1426032000, 1426035599 ],
        [ 'Hourly First End'     , 3600,  1426035599, 1426032000, 1426035599 ],
        [ 'Hourly Second Start'  , 3600,  1426035600, 1426035600, 1426039199 ],
        [ 'Hourly Second Middle' , 3600,  1426035650, 1426035600, 1426039199 ],
        [ 'Hourly Second End'    , 3600,  1426039199, 1426035600, 1426039199 ],
        [ 'Irregular Interval'   , 3604,  1426034321, 1426034321, 1426037924 ],
    ];

    foreach my $test ( @$data ) {
        my ( $name, $interval, $now, $begin, $end ) = @$test;
        my ( $c_begin, $c_end ) = $dmarc->get_report_window( $interval, $now );
        is_deeply( [ $c_begin, $c_end ] , [ $begin, $end ] , "Report Window: $name" ); 
    }

}

sub test_interval_limits {

    my $data = [
        [ 'Below Limit'    , 3600, 86400, 3000,  3600  ],
        [ 'Lower Limit'    , 3600, 86400, 3600,  3600  ],
        [ 'Between Limits' , 3600, 86400, 30000, 30000 ],
        [ 'Upper Limit'    , 3600, 86400, 86400, 86400 ],
        [ 'Above Limit'    , 3600, 86400, 87000, 86400 ],
    ];

    my $now = 1426035650;
    foreach my $test ( @$data ) {
        my ( $name, $min, $max, $interval, $expect ) = @$test;
        $dmarc->config->{'report_sending'}->{'min_interval'} = $min;
        $dmarc->config->{'report_sending'}->{'max_interval'} = $max;
        my ( $c_begin, $c_end ) = $dmarc->get_report_window( $interval, $now );
        is_deeply( ( $c_end - $c_begin ), $expect - 1, "Interval Limit: $name" ); 
    }
    delete $dmarc->config->{'report_sending'}->{'min_interval'};
    delete $dmarc->config->{'report_sending'}->{'max_interval'};
}

sub test_dkim {
    # set DKIM with key=>val pairs
    $dmarc->{dkim} = undef;
    my %test_dkim1 = ( domain => 'a.c', result => 'fail', selector => undef, human_result => undef );
    my %test_dkim2 = ( domain => 'a.b.c', result => 'pass' );

    ok( $dmarc->dkim(%test_dkim1), "dkim, hash set" );
    is_deeply($dmarc->dkim, [ \%test_dkim1 ], "dkim, hash set result");

    # set with a hashref
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim(\%test_dkim1), "dkim, hashref set" );
    is_deeply($dmarc->dkim, [ \%test_dkim1 ], "dkim, hashref set, result");

    # set with an arrayref
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim([ \%test_dkim1 ]), "dkim, arrayref set" );
    is_deeply($dmarc->dkim, [ \%test_dkim1 ], "dkim, arrayref set result");

    # set with arrayref, two values
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim([ \%test_dkim1, \%test_dkim2 ]), "dkim, arrayref set" );
    is_deeply($dmarc->dkim, [ \%test_dkim1, \%test_dkim2 ], "dkim, arrayref set result");

    # set with hashes, iterative
    $dmarc->{dkim} = undef;
    ok( $dmarc->dkim(%test_dkim1), "dkim, hash set 1" );
    ok( $dmarc->dkim(%test_dkim2), "dkim, hash set 2" );
    is_deeply($dmarc->dkim, [ \%test_dkim1, \%test_dkim2 ], "dkim, iterative hashes");

    # set with a Mail::DKIM::Verifier
    $dmarc->{dkim} = undef;
    my $dkv = Mail::DKIM::Verifier->new( %test_dkim1 );
    $dmarc->dkim( $dkv );
    is_deeply( $dmarc->dkim, [ \%test_dkim1 ], "dkim, as Mail::DKIM::Verifier");


    # set with a callback
    $dmarc->{dkim} = undef;
    my $counter  = 0;
    my $callback = sub { $counter++; [ \%test_dkim1 ] };
    ok( $dmarc->dkim($callback), "dkim, arrayref set" );
    is($counter, 0, "callback not yet called");
    is_deeply($dmarc->dkim, [ \%test_dkim1 ], "dkim, callback-derived result");
    is_deeply($dmarc->dkim, [ \%test_dkim1 ], "dkim, callback-cached result");
    is($counter, 1, "callback exactly once");

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
    $dmarc->init;
    my %test_spf = ( domain => 'a.c', scope => 'mfrom', result => 'fail' );

    ok( $dmarc->spf(%test_spf), "spf, hash set" );
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, hash set result");

    # set with a hashref
    $dmarc->init;
    ok( $dmarc->spf(\%test_spf), "spf, hashref set" );
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, hashref set, result");

    # set with an arrayref
    $dmarc->init;
    ok( $dmarc->spf([ \%test_spf ]), "spf, arrayref set" );
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, arrayref set result");

    # set with arrayref, two values
    $dmarc->init;
    ok( $dmarc->spf([ \%test_spf, \%test_spf ]), "spf, arrayref set" );
    is_deeply($dmarc->spf, [ \%test_spf, \%test_spf ], "spf, arrayref set result");

    # set with a callback
    $dmarc->init;
    my $counter  = 0;
    my $callback = sub { $counter++; [ \%test_spf ] };
    ok( $dmarc->spf($callback), "spf, callback set" );
    is($counter, 0, "callback not yet called");
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, callback-derived result");
    is_deeply($dmarc->spf, [ \%test_spf ], "spf, callback-cached result");
    is($counter, 1, "callback exactly once");

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
    my $expected = { config_file => 'mail-dmarc.ini' };
    is_deeply( $dmarc, $expected, "new, empty" );

    # new, one shot request
    $dmarc = cleanup_obj( Mail::DMARC->new(%sample_dmarc) );
    isa_ok( $dmarc, 'Mail::DMARC' );
    is_deeply( $dmarc, \%sample_dmarc, "new, one shot" );


    # new, individual accessors
    $dmarc = Mail::DMARC->new();
    foreach my $key ( keys %sample_dmarc ) {
        next if grep {/$key/} qw/ config config_file public_suffixes /;
        my $val = $sample_dmarc{$key};
        $dmarc->$key( $val )
            or diag "error running $key with $val arg: $@";
    }
    $dmarc = cleanup_obj($dmarc);
    is_deeply($dmarc, \%sample_dmarc, "new, individual accessors" );
}

sub test_config_file_first {
    # config file loaded before any other attr initialization
    my $new_dmarc = Mail::DMARC::Testing->new(
        config_file => 't/mail-dmarc.ini',
        assert_ok   => 1,
    );
};

sub cleanup_obj {
    my $obj = shift;
    foreach my $k ( qw/ config public_suffixes dkim_ar spf_ar / ) {
        delete $obj->{$k};
    }
    return $obj;
}


package Mail::DKIM::Verifier;
sub new {
    my ($class, %args) = @_;
    my $self = bless { signatures => [] }, $class;
    $self->signatures(%args);
    return $self;
}
sub signatures {
    my $self = shift;
    return shift @{ $self->{signatures}} if 0 == scalar @_;
    push @{ $self->{signatures} }, Mail::DKIM::Signature->new(@_);
    $self->{signatures};
}
1;

package Mail::DKIM::Signature;
sub new { my $class = shift; return bless { @_ }, $class; };
sub result { return $_[0]->{result}; }
sub domain { return $_[0]->{domain}; }
sub selector { return $_[0]->{selector}; }
sub result_detail {
    return $_[0]->{result_detail} || $_[0]->{human_result};
}
1;

package Mail::DMARC::Testing;
use parent 'Mail::DMARC';
sub assert_ok {
    my ($self) = @_;
    Test::More::is(
        $self->config->{organization}{domain},
        'example-test.com',
        'config file is initialized before assert_ok',
    );
}
1;
