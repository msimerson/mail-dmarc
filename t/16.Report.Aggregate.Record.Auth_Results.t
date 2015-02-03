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
    is_deeply([], $ar->spf, "spf, empty");

    my %spf_res = (
        domain => 'test.com',
        result => 'pass',
        scope  => 'mfrom',
        );

    $ar->spf( %spf_res );
    is_deeply([ \%spf_res ], $ar->spf, "spf, hash");

    $ar->spf( %spf_res );
    is_deeply([ \%spf_res, \%spf_res ], $ar->spf, "spf, hashref");

    $ar = $mod->new;
    $ar->spf([ \%spf_res, \%spf_res ]);
    is_deeply([ \%spf_res, \%spf_res ], $ar->spf, "spf, arrayref of hashref");

    #warn Dumper($ar->spf);
}

sub _dkim {
    is_deeply([], $ar->dkim, "dkim");

    my %dkim_res = (
        domain      => 'tnpi.net',
        selector    => 'jan2015',
        result      => 'fail',
        human_result=> 'fail (body has been altered)',
    );

    $ar->dkim( %dkim_res );
    is_deeply([ \%dkim_res ], $ar->dkim, "dkim, as hash");


    $ar->dkim( \%dkim_res );
    is_deeply([ \%dkim_res, \%dkim_res ], $ar->dkim, "dkim, as hashref");

    $ar->dkim( \%dkim_res );
    is_deeply([ \%dkim_res, \%dkim_res, \%dkim_res ], $ar->dkim, "dkim, as hashref again");


    $ar = $mod->new;
    $ar->dkim([ \%dkim_res, \%dkim_res ]);
    is_deeply([ \%dkim_res, \%dkim_res ], $ar->dkim, "dkim, as arrayref of hashrefs");


    $ar = $mod->new;
    my $dkv = Mail::DKIM::Verifier->new( %dkim_res );
    $ar->dkim( $dkv );
    is_deeply([ \%dkim_res ], $ar->dkim, "dkim, as Mail::DKIM::Verifier");

    #warn Dumper($ar->dkim);
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
