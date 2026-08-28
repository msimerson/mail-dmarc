package Mail::DMARC::HTTP;
our $VERSION = '2.20260724';
use strict;
use warnings;
use feature 'signatures';
use feature 'try';
no warnings 'experimental::try';    ## no critic (ProhibitNoWarnings)

use parent 'Net::Server::HTTP';

use CGI;
use Data::Dumper;
use File::ShareDir;
use IO::Uncompress::Gunzip;
use JSON -convert_blessed_universally;
use URI;

our $report;
use Mail::DMARC::PurePerl;

my %mimes = (
    css  => 'text/css',
    html => 'text/html',
    js   => 'application/javascript',
    json => 'application/json',
);

sub new($class) {
    return bless {}, $class;
}

sub dmarc_httpd( $self, $http_report ) {
    $report = $http_report;

    my $port   = $report->config->{http}{port} || 8080;
    my $ports  = $report->config->{https}{port};
    my $sslkey = $report->config->{https}{ssl_key};
    my $sslcrt = $report->config->{https}{ssl_crt};

    Net::Server::HTTP->run(
        app  => sub {&dmarc_dispatch},
        port => [ $port, ( ( $ports && $sslkey && $sslcrt ) ? "$ports/ssl" : () ) ],
        ipv  => '*',    # IPv6 if available
        ( $sslkey ? ( SSL_key_file  => $sslkey ) : () ),
        ( $sslcrt ? ( SSL_cert_file => $sslcrt ) : () ),
        log_file        => 'Sys::Syslog',
        syslog_ident    => 'mail_dmarc',
        syslog_facility => 'MAIL',
    );
    return;
}

sub dmarc_dispatch($self) {
    my $path = $self->{request_info}{request_path};
    if ($path) {
        warn "path: $path\n";

        # Parse QUERY_STRING once here via URI (not CGI->new->Vars) to avoid
        # CGI.pm state issues in persistent Net::Server::HTTP processes.
        my %vars
            = URI->new( 'http://x/?' . ( $ENV{QUERY_STRING} // '' ) )->query_form;
        return report_json_report( \%vars ) if $path eq '/dmarc/json/report';
        return report_json_rr( \%vars )     if $path eq '/dmarc/json/row';
        return report_json_domains( \%vars ) if $path eq '/dmarc/json/domains';
        return serve_validator()            if $path eq '/dmarc/json/validate';

        my %agg = (
            '/dmarc/json/summary'    => 'get_summary',
            '/dmarc/json/timeseries' => 'get_timeseries',
            '/dmarc/json/sources'    => 'get_sources',
            '/dmarc/json/source'     => 'get_source_detail',
        );
        return report_json_agg( $agg{$path}, \%vars ) if $agg{$path};
        return serve_file($path)            if $path =~ /\.(?:js|css|html|gz)$/x;
    }

    return serve_file('/dmarc/index.html');
}

sub serve_pretty_error( $error = undef ) {
    $error ||= 'Sorry, that operation is not supported.';
    return print <<"EO_ERROR"
Content-Type: text/html

<p>$error</p>

EO_ERROR
        ;
}

sub return_json_error($err) {

    #warn $err;
    print JSON->new->utf8->encode( { err => $err } );    # to HTTP client
    print "\n";
    return $err;                                         # to caller
}

sub serve_validator( $cgi = undef, $resolver = undef ) {
    $cgi ||= CGI->new();    # passed in $cgi for testing
    my $json = JSON->new->utf8;

    print $cgi->header("application/json");

    my $post = $cgi->param('POSTDATA');
    if ( !$post ) { return return_json_error("missing POST data"); }

    my ( $input, $dmpp, $res );
    try {
        $input = $json->decode($post);
    }
    catch ($error) {
        return return_json_error($error);
    }

    if ( !$input || !ref $input ) {
        return return_json_error("invalid request $post");
    }

    try {
        $dmpp = Mail::DMARC::PurePerl->new(%$input);
    }
    catch ($error) {
        return return_json_error($error);
    }

    $dmpp->set_resolver($resolver) if $resolver;

    try {
        $res = $dmpp->validate();
    }
    catch ($error) {
        return return_json_error($error);
    }

    my $return = $json->allow_blessed->convert_blessed->encode($res);
    print "$return\n";
    return $return;
}

# The viewer's assets are a known set of plain names, so each path segment is
# matched against what is allowed rather than checked for what is not. A
# blacklist of traversal sequences has to anticipate every encoding that
# survives the request parser; requiring a leading alphanumeric rejects '.',
# '..' and dotfiles outright, and leaves no way to name a directory above the
# share directory.
my $SAFE_SEGMENT = qr/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/x;

sub serve_file($path) {
    my @bits = split /\//, $path;
    shift @bits;
    return serve_pretty_error("file not found")
        if ( !$bits[0] || 'dmarc' ne $bits[0] );
    shift @bits;

    return serve_pretty_error("no such file") if !@bits;
    foreach my $bit (@bits) {
        return serve_pretty_error("no such file") if $bit !~ $SAFE_SEGMENT;
    }

    $path = join '/', @bits;
    my $file = $bits[-1];

    my ($extension) = ( split /\./, $file )[-1];
    return serve_pretty_error("$extension not recognized") if !$mimes{$extension};

    my $dir = "share/html";    # distribution dir
    if ( !-d $dir ) {
        $dir = File::ShareDir::dist_dir('Mail-DMARC');    # installed loc.
        $dir .= "/html";
    }
    return serve_pretty_error("no such path") if !$dir;
    return serve_gzip("$dir/$path.gz")        if -f "$dir/$path.gz";
    return serve_pretty_error("no such file") if !-f "$dir/$path";

    open my $FH, '<', "$dir/$path"
        or return serve_pretty_error("unable to read $dir/$path: $!");
    print "Content-Type: $mimes{$extension}\n\n";
    print <$FH>;
    close $FH;
    return 1;
}

sub serve_gzip($file) {
    open my $FH, '<', "$file"
        or return serve_pretty_error("unable to read $file: $!");
    my $contents = do { local $/; <$FH> };    ## no critic (Local)
    close $FH;

    my $decomp = substr( $file, 0, -3 );             # remove .gz suffix
    my ($extension) = ( split /\./, $decomp )[-1];

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
    }

    # browser doesn't support gzip, decompress and serve
    my $out;
    IO::Uncompress::Gunzip::gunzip( \$contents => \$out )
        or return serve_pretty_error("unable to decompress");
    my $length = length $out;

    return print <<"EO_UNGZ"
Content-Length: $length
Content-Type: $mimes{$extension}

$out
EO_UNGZ
        ;
}

my @AGG_INT_PARAMS = qw/ since until start length /;
my @AGG_STR_PARAMS = qw/ from_domain author source_ip sort_col /;

# Which reports to count: those others sent us about our domains, those this
# host is preparing to send about other people's, or both.
my %AGG_REPORT_KINDS = map { $_ => 1 } qw/ received outgoing all /;

my $AGG_DEFAULT_DAYS = 30;

sub agg_params($vars) {
    my %args;

    foreach my $param (@AGG_INT_PARAMS) {
        next if !defined $vars->{$param};
        next if $vars->{$param} !~ /\A-?[0-9]{1,12}\z/x;
        $args{$param} = 0 + $vars->{$param};
    }

    foreach my $param (@AGG_STR_PARAMS) {
        next if !defined $vars->{$param} || '' eq $vars->{$param};
        next if length $vars->{$param} > 253;
        $args{$param} = $vars->{$param};
    }

    $args{reports} = $vars->{reports}
        if defined $vars->{reports} && $AGG_REPORT_KINDS{ $vars->{reports} };

    # Without a default window an unparameterized request would aggregate the
    # entire report history.
    $args{until} //= time;
    $args{since} //= $args{until} - ( $AGG_DEFAULT_DAYS * 86400 );

    return %args;
}

sub serve_json($data) {
    print "Content-Type: application/json\n\n";
    print encode_json $data;
    return;
}

sub report_json_agg( $method, $vars ) {
    my $backend = $report->store->backend;
    if ( !$backend->can($method) ) {
        print "Content-Type: application/json\n\n";
        return return_json_error("report store does not support $method");
    }

    my $data;
    try {
        $data = $backend->$method( agg_params($vars) );
    }
    catch ($error) {
        print "Content-Type: application/json\n\n";
        return return_json_error("$error");
    }

    return serve_json($data);
}

sub report_json_domains($vars) {
    my $data;
    my @args;
    push @args, reports => $vars->{reports}
        if defined $vars->{reports} && $AGG_REPORT_KINDS{ $vars->{reports} };
    try {
        $data = $report->store->backend->get_report_domains(@args);
    }
    catch ($error) {
        print "Content-Type: application/json\n\n";
        return return_json_error("$error");
    }

    return serve_json($data);
}

sub report_json_report($vars) {
    my %args = %$vars;
    delete $args{reports}
        if defined $args{reports} && !$AGG_REPORT_KINDS{ $args{reports} };
    return serve_json( $report->store->backend->get_report(%args) );
}

sub report_json_rr($vars) {
    return serve_json(
        $report->store->backend->get_rr( rid => $vars->{rid} ) );
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::HTTP - view stored reports via HTTP

=head1 VERSION

version 2.20260724

=head1 SYNOPSIS

See the POD docs / man page for L<dmarc_httpd>.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=item *

Marc Bradshaw <marc@marcbradshaw.net>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2026 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
