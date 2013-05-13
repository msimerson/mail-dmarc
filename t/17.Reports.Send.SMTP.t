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

open my $REP, '<', 'share/dmarc-report-2013-draft.xsd' or die "unable to open";
my $report = join('', <$REP>);
close $REP;
my $zipped;
IO::Compress::Gzip::gzip( \$report, \$zipped ) or die "unable to compress";
#print Dumper($report);
my $subject = $smtp->get_subject({to=>'they.com',policy_domain=>'them.com'});
ok( $subject, "get_subject, $subject");
my %email_args = (
        to            => 'matt@example.com',
        from          => 'do-not-reply@example.com',
        subject       => $subject,
        body          => 'This is is the body of a test. It is only a test',
        report        => $zipped,
        policy_domain => 'foo.com',
        begin         => time,
        end           => time + 3600,
        );

test_get_to_dom();
test_get_smtp_hosts();
test_assemble_message();

# to spam yourself with 'make test', set 'to' in %email_args
done_testing(); exit;      # and comment this out

#test_via_net_smtp();
$smtp->email( %email_args );

done_testing();
exit;

sub test_assemble_message {
    my $mess = $smtp->_assemble_message( \%email_args );
    ok( $mess, "_assemble_message");
#warn print $mess;
};

sub test_net_smtp {
    ok( $smtp->via_net_smtp( \%email_args ),"via_net_smtp, example.com");
#ok( $smtp->via_net_smtp( { to=>'test.user@gmail.com' } ),"via_net_smtp, gmail");
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
