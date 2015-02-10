use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Aggregate::Record::Auth_Results';
use_ok($mod);
my $ar = $mod->new;

_auth_results();
_spf();
_dkim();

done_testing();
exit;

sub _auth_results {
    isa_ok( $ar, $mod );
};

sub _spf {
    is_deeply( $ar->spf, [], "spf, empty");

    my %spf_res = (
        domain => 'test.com',
        result => 'pass',
        scope  => 'mfrom',
        );

    $ar->spf( %spf_res );
    is_deeply( $ar->spf, [ \%spf_res ], "spf, hash");

    $ar->spf( %spf_res );
    is_deeply( $ar->spf, [ \%spf_res, \%spf_res ], "spf, hashref");

    $ar = $mod->new;
    $ar->spf([ \%spf_res, \%spf_res ]);
    is_deeply( $ar->spf, [ \%spf_res, \%spf_res ], "spf, arrayref of hashref");

    #warn Dumper($ar->spf);
}

sub _dkim {
    is_deeply( $ar->dkim, [], "dkim");

    my %dkim_res = (
        domain      => 'tnpi.net',
        selector    => 'jan2015',
        result      => 'fail',
        human_result=> 'fail (body has been altered)',
    );

    $ar->dkim( %dkim_res );
    is_deeply( $ar->dkim, [ \%dkim_res ], "dkim, as hash");


    $ar->dkim( \%dkim_res );
    is_deeply( $ar->dkim, [ \%dkim_res, \%dkim_res ], "dkim, as hashref");

    $ar->dkim( \%dkim_res );
    is_deeply( $ar->dkim, [ \%dkim_res, \%dkim_res, \%dkim_res ], "dkim, as hashref again");


    $ar = $mod->new;
    $ar->dkim([ \%dkim_res, \%dkim_res ]);
    is_deeply( $ar->dkim, [ \%dkim_res, \%dkim_res ], "dkim, as arrayref of hashrefs");

    #warn Dumper($ar->dkim);
}
