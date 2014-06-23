package Mail::DMARC::HTTP;
our $VERSION = '1.20140623'; # VERSION
use strict;
use warnings;

use parent 'Net::Server::HTTP';

use CGI;
use Data::Dumper;
use File::ShareDir;
use IO::Uncompress::Gunzip;
use JSON -convert_blessed_universally;
use URI;

use lib 'lib';
use Mail::DMARC;
use Mail::DMARC::PurePerl;
my $dmarc = Mail::DMARC->new();
my $report = $dmarc->report;

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
        port  => [$port, (($ports && $sslkey && $sslcrt) ? "$ports/ssl" : ()) ],
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
    if ($path) {
        warn "path: $path\n";
        return report_json_report()  if $path eq '/dmarc/json/report';
        return report_json_rr()      if $path eq '/dmarc/json/row';
        return serve_validator()     if $path eq '/dmarc/json/validate';
        return serve_file($path)     if $path =~ /\.(?:js|css|html|gz)$/x;
    };

    return serve_file('/dmarc/index.html');
};

sub serve_pretty_error {
    my $error = shift || 'Sorry, that operation is not supported.';
    return print <<"EO_ERROR"
Content-Type: text/html

<p>$error</p>

EO_ERROR
;
};

sub serve_validator {
    my $cgi  = CGI->new();
    my $json = JSON->new->utf8;
    my $input= $json->decode( $cgi->param('POSTDATA') );
    my ($dmpp, $res);
    eval { $dmpp = Mail::DMARC::PurePerl->new( %$input ) };
    if ($@) { $res = { err => $@ }; }
    else {
        eval { $res  = $dmpp->validate() };
        if ($@) { $res = { err => $@ }; };
    };
    print $cgi->header("application/json");
    print $json->allow_blessed->convert_blessed->encode( $res );
    return;
};

sub serve_file {
    my ($path) = @_;

    my @bits = split /\//, $path;
    shift @bits;
    return serve_pretty_error("file not found") if (!$bits[0] || 'dmarc' ne $bits[0]);
    shift @bits;
    $path = join '/', @bits;
    my $file = $bits[-1];
    $file =~ s/[^[ -~]]//g;  # strip out any non-printable chars

    my ($extension) = (split /\./, $file)[-1];
    return serve_pretty_error("$extension not recognized") if ! $mimes{$extension};

    my $dir = "share/html";  # distribution dir
    if ( ! -d $dir ) {
        $dir = File::ShareDir::dist_dir( 'Mail-DMARC' ); # installed loc.
        $dir .= "/html";
    };
    return serve_pretty_error("no such path") if ! $dir;
    return serve_gzip("$dir/$path.gz") if -f "$dir/$path.gz";
    return serve_pretty_error("no such file") if ! -f "$dir/$path";

    open my $FH, '<', "$dir/$path" or
        return serve_pretty_error( "unable to read $dir/$path: $!" );
    print "Content-Type: $mimes{$extension}\n\n";
    print <$FH>;
    close $FH;
    return 1;
};

sub serve_gzip {
    my $file = shift;

    open my $FH, '<', "$file" or
        return serve_pretty_error( "unable to read $file: $!" );
    my $contents = do { local $/; <$FH> };    ## no critic (Local)
    close $FH;

    my $decomp = substr($file, 0, -3);  # remove .gz suffix
    my ($extension) = (split /\./, $decomp)[-1];

# browser accepts gz encoding, serve compressed
    if ( grep {/gzip/} $ENV{HTTP_ACCEPT_ENCODING} ) {
        my $length = length $contents;
        return print <<"EO_GZ"
Content-Length: $length
Content-Type: $mimes{$extension}
Content-Encoding: gzip

$contents
EO_GZ
;
    };

    # browser doesn't support gzip, decompress and serve
    my $out;
    IO::Uncompress::Gunzip::gunzip( \$contents => \$out )
         or return serve_pretty_error( "unable to decompress" );
    my $length = length $out;

    return print <<"EO_UNGZ"
Content-Length: $length
Content-Type: $mimes{$extension}

$out
EO_UNGZ
;
};

sub report_json_report {
    print "Content-type: application/json\n\n";
    my $reports = $report->store->backend->get_report( CGI->new->Vars );
    print encode_json $reports;
    return;
};

sub report_json_rr {
    print "Content-type: application/json\n\n";
    my $row = $report->store->backend->get_rr( CGI->new->Vars );
    print encode_json $row;
#   warn Dumper($row);
    return;
};

1;

# ABSTRACT: view stored reports via HTTP

__END__

=pod

=head1 NAME

Mail::DMARC::HTTP - view stored reports via HTTP

=head1 VERSION

version 1.20140623

=head1 SYNOPSIS

See the POD docs / man page for L<dmarc_httpd>.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by ColocateUSA.com.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
