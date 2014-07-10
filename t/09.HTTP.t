use strict;
use warnings;

use CGI;
use Data::Dumper;
use Test::More;

use lib 'lib';

foreach my $req ( 'DBD::SQLite 1.31', 'Net::Server::HTTP' ) {
    eval "use $req";
    if ($@) {
        plan( skip_all => "$req not available" );
        exit;
    }
};

my $mod = 'Mail::DMARC::HTTP';
use_ok($mod);
my $http = $mod->new;
isa_ok( $http, $mod );

my $cgi = CGI->new();
my $r = Mail::DMARC::HTTP::serve_validator($cgi);
ok($r eq 'missing POST data', "serve_validator, missing POST data");

$cgi->param('POSTDATA', 'foo');
$r = Mail::DMARC::HTTP::serve_validator($cgi);
like($r, qr/expected/, "serve_validator, invalid JSON");

$cgi->param('POSTDATA', '{"foo":"bar"}');
$r = Mail::DMARC::HTTP::serve_validator($cgi);
like($r, qr/no header_from/, "serve_validator, missing header_from");

$cgi->param('POSTDATA', '{"header_from":"tnpi.net"}');
$r = Mail::DMARC::HTTP::serve_validator($cgi);
like($r, qr/missing SPF/, "serve_validator, missing SPF");

$cgi->param('POSTDATA', '{"header_from":"tnpi.net","spf":[{"domain":"tnpi.net","scope":"mfrom","result":"pass"}]}');
$r = Mail::DMARC::HTTP::serve_validator($cgi);
like($r, qr/pass/, "serve_validator, pass SPF");

# this starts up the httpd daemon
#$http->dmarc_httpd();

done_testing();
exit;
