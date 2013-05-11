use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 'lib';

my $mod = 'Mail::DMARC::Report::Send::SMTP';
use_ok( $mod );
my $smtp = $mod->new;
isa_ok( $smtp, $mod );

eval { $smtp->email };
chomp $@;
ok( $@, "email, missing args" );

test_get_to_dom();
test_get_smtp_hosts();
test_net_smtp();
done_testing(); exit;   # comment this out to spam yourself with 'make test'

$smtp->email(
        to      => 'admin@example.com',
        from    => 'do-not-reply@example.com',
        subject => 'Mail::DMARC::Report::Send::SMTP test',
        body    => 'This is a test. It is only a test',
        );


done_testing();
exit;

sub test_net_smtp {
    ok( $smtp->net_smtp( { from=>'matt@example.com',to=>'matt@example.com' } ),"net_smtp, example.com");
#ok( $smtp->net_smtp( { to=>'test.user@gmail.com' } ),"net_smtp, gmail");
};

sub test_get_smtp_hosts {
    my $initial_smarthost = $smtp->config->{smtp}{smarthost};
    $smtp->config->{smtp}{smarthost} = 'foo.example.com';
    is_deeply( $smtp->get_smtp_hosts('bar.com'), [ {addr=>'foo.example.com'} ], "get_smtp_hosts, smarthost");

    $smtp->config->{smtp}{smarthost} = undef;
    is_deeply( $smtp->get_smtp_hosts('tnpi.net'), [ { pref=>10,addr=>'mail.theartfarm.com'} ], "get_smtp_hosts, tnpi.net");

    $smtp->config->{smtp}{smarthost} = $initial_smarthost;
};

sub test_get_to_dom {

    my %valids = (
            'do-not-reply@example.com' => 'example.com',
            );

    foreach ( keys %valids ) {
        cmp_ok( $smtp->get_to_dom({to=>$_}), 'eq', $valids{$_}, "get_to_dom, $_");
    };
};
