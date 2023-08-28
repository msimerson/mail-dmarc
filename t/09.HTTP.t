use strict;
use warnings;

use Data::Dumper;
use Net::DNS::Resolver::Mock;
use Test::More;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

use lib 'lib';

foreach my $req ( 'CGI', 'DBD::SQLite 1.31', 'JSON', 'Net::Server::HTTP' ) {
    eval "use $req";
    if ($@) {
        plan( skip_all => "$req not available" );
        exit;
    }
};

my $resolver = new Net::DNS::Resolver::Mock();
$resolver->zonefile_parse(join("\n",
'tnpi.net.                         600 A   66.128.51.170',
'_dmarc.tnpi.net.                  600 TXT "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@theartfarm.com; ruf=mailto:dmarc-feedback@theartfarm.com; pct=100"',
#'tnpi.net.                         600 MX  10 mail.theartfarm.com.',
''));

my $mod = 'Mail::DMARC::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

my $cgi = CGI->new();
my $r = Mail::DMARC::HTTP::serve_validator($cgi, $resolver);
ok($r eq 'missing POST data', "serve_validator, missing POST data");

$cgi->param('POSTDATA', 'foo');
$r = Mail::DMARC::HTTP::serve_validator($cgi, $resolver);
like($r, qr/expected/, "serve_validator, invalid JSON");

$cgi->param('POSTDATA', '{"foo":"bar"}');
$r = Mail::DMARC::HTTP::serve_validator($cgi, $resolver);
like($r, qr/no header_from/, "serve_validator, missing header_from");

$cgi->param('POSTDATA', '{"header_from":"tnpi.net"}');
$r = Mail::DMARC::HTTP::serve_validator($cgi, $resolver);
like($r, qr/"spf":""/, "serve_validator, missing SPF");
like($r, qr/"dkim":"fail"/, "serve_validator, missing DKIM");

$cgi->param('POSTDATA', '{"header_from":"tnpi.net","spf":[{"domain":"tnpi.net","scope":"mfrom","result":"pass"}]}');
$r = Mail::DMARC::HTTP::serve_validator($cgi, $resolver);
like($r, qr/"spf":"pass"/, "serve_validator, pass SPF");
like($r, qr/"dkim":"fail"/, "serve_validator, missing DKIM");

$cgi->param('POSTDATA', '{"header_from":"tnpi.net","dkim":[{"domain":"tnpi.net","selector":"mar2013","result":"pass"}]}');
$r = Mail::DMARC::HTTP::serve_validator($cgi, $resolver);
like($r, qr/"spf":""/, "serve_validator, missing SPF");
like($r, qr/"dkim":"pass"/, "serve_validator, pass DKIM");

# this starts up the httpd daemon
#$http->dmarc_httpd();

done_testing();
