package Mail::DMARC::Report::View::HTTP;
use strict;
use warnings;

# use HTTP::Server::Simple;  # a possibility?
# use HTTP::Daemon;          # nope, IPv4 only

use parent 'Net::Server::HTTP';

use CGI;
use Data::Dumper;
use File::ShareDir;
use JSON;
use URI;

use lib 'lib';
require Mail::DMARC::Report;
my $report = Mail::DMARC::Report->new;

my %mimes  = (
    css  => 'text/css',
    html => 'text/html',
    js   => 'application/javascript',
    json => 'application/json',
);

sub new {
    my $class = shift;
    return bless {}, $class;
};

sub dmarc_httpd {
    my $self = shift;

    my $port   = $report->config->{http}{port}   || 8080;
    my $ports  = $report->config->{https}{port};
    my $sslkey = $report->config->{https}{ssl_key};
    my $sslcrt = $report->config->{https}{ssl_crt};

    Net::Server::HTTP->run(
        app => sub { &dmarc_dispatch },
        port  => [$port, ($ports ? "$ports/ssl" : ()) ],
        ipv   => '*', # IPv6 if available
        ($sslkey ? (SSL_key_file => $sslkey) : ()),
        ($sslcrt ? (SSL_cert_file => $sslcrt) : ()),
    );
    return;
};

sub dmarc_dispatch {
    my $self = shift;

#   warn Dumper( { CGI->new->Vars } );

    my $path = $self->{request_info}{request_path};
    if ( $path ) {
        warn "path: $path\n";
        return report_json_report($self) if $path eq '/dmarc/json/report';
        return report_json_row($self)    if $path eq '/dmarc/json/row';
        return serve_file($self,$path)   if $path =~ /\.(?:js|css|html)$/x;
    };

    return serve_file($self,'/dmarc/index.html');
};

sub serve_pretty_error {
    my $error = shift || 'Sorry, that operation is not supported.';
        ;
    print <<"EO_ERROR"
Content-Type: text/html

<p>$error</p>

EO_ERROR
;
    return;
};

sub serve_file {
    my ($http,$path) = @_;

    my @bits = split /\//, $path;
    shift @bits;
    return serve_pretty_error("file not found") if 'dmarc' ne $bits[0];
    shift @bits;
    $path = join '/', @bits;
#warn "url path: $path<br>\n";
    my $file = $bits[-1];
    $file =~ s/[^[ -~]]//g;  # strip out any non-printable chars
#warn "parsed file: $file<br>\n";

    my ($extension) = (split /\./, $file)[-1];
#warn "parsed extension: $extension<br>\n";
    return serve_pretty_error("$extension not recognized") if ! $mimes{$extension};

    print "Content-Type: $mimes{$extension}\n\n";

    my $dir = "share/html";  # distribution dir
    if ( ! -d $dir ) {
        $dir = File::ShareDir::dist_dir( 'Mail-DMARC' ); # installed loc.
        $dir .= "/html";
#warn "sharedir: $dir\n";
    };
#warn "serve dir: $dir<br>\n";
    return serve_pretty_error("no such path") if ! $dir;
    return serve_pretty_error("no such file") if ! -f "$dir/$path";
#warn "200 $dir/$path\n";
    open my $FH, '<', "$dir/$path" or
        return serve_pretty_error( "unable to read $dir/$path: $!" );
    print <$FH>;
    close $FH;
    return 1;
};


sub report_json_report {
    print "Content-type: application/json\n\n";
    my $reports = $report->store->backend->get_report( CGI->new->Vars );
    print encode_json $reports;
    return;
};

sub report_json_row {
    print "Content-type: application/json\n\n";
    my $row = $report->store->backend->get_row( CGI->new->Vars );
    print encode_json $row;
#   warn Dumper($row);
    return;
};

1;

# ABSTRACT: view stored reports via HTTP
__END__

=head1 SYNOPSIS

See the POD docs / man page for L<dmarc_httpd>.

=cut
