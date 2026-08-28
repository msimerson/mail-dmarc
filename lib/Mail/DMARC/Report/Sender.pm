package Mail::DMARC::Report::Sender;

use strict;
use warnings;
use feature 'signatures';
use feature 'try';
no warnings 'experimental::try';    ## no critic (ProhibitNoWarnings)

use Carp;
use Encode;
use Getopt::Long;
use Sys::Syslog qw(:standard :macros);
use Mail::DMARC::Report;
use Email::Sender::Simple qw{ sendmail };
use Email::Sender::Transport::SMTP;
use Email::Sender::Transport::SMTP::Persistent;
use Module::Load;
use Scalar::Util qw(blessed refaddr);

sub new( $class, $args = undef ) {
    $args ||= {};
    my $self = {
        send_delay        => $args->{delay}             // 5,
        batch_size        => $args->{batch}             // 1,
        alarm_at          => $args->{timeout}           // 120,
        syslog            => $args->{syslog}            // 0,
        smarthost         => $args->{smarthost}         // undef,
        transports_method => $args->{transports_method} // undef,
        transports_object => $args->{transports_object} // undef,
        dkim_key          => $args->{dkim_key}          // undef,
        verbose           => $args->{verbose}           // 0,
    };
    return bless $self, $class;
}

sub set_transports_object( $self, $transports_object ) {
    $self->{transports_object} = $transports_object;
    return;
}

sub set_transports_method( $self, $transports_method ) {
    $self->{transports_method} = $transports_method;
    return;

    # Transports method is a sub which returns
    # a list of transports for the given args.
}

my %SMART_SSL = map { $_ => 1 } qw/ starttls maybestarttls ssl /;

# The submission ports each imply how TLS is negotiated on them.
my %PORT_TLS = ( 465 => 'ssl', 587 => 'starttls' );

sub smarthost_transports( $self, $report ) {
    my $smtp = $report->config->{smtp};

    my %common = (
        host    => $smtp->{smarthost},
        helo    => $report->sendit->smtp->get_helo_hostname,
        timeout => 32,
    );

    my %auth;
    if ( $smtp->{smartuser} ) {
        $auth{sasl_username} = $smtp->{smartuser};
        $auth{sasl_password} = $smtp->{smartpass} if $smtp->{smartpass};
    }

    my $configured = $self->smarthost_ssl_configured($report);

    if ( my $port = $smtp->{smartport} ) {
        return $self->smarthost_route( \%common, \%auth, $port,
            $self->smarthost_ssl($report) )
            if $configured;
        return $self->smarthost_route( \%common, \%auth, $port,
            $PORT_TLS{$port} )
            if $PORT_TLS{$port};
        return $self->smarthost_route( \%common, \%auth, $port,
            %auth ? 'starttls' : 'maybestarttls' );
    }

    if ($configured) {
        my $ssl = $self->smarthost_ssl($report);
        return $self->smarthost_route( \%common, \%auth,
            ( 'ssl' eq ( $ssl || q{} ) ? 465 : 25 ), $ssl );
    }

    return (
        $self->smarthost_route( \%common, \%auth, 465, 'ssl' ),
        $self->smarthost_route( \%common, \%auth, 587, 'starttls' ),
        $self->smarthost_route( \%common, \%auth, 25, 'starttls' ),
    ) if %auth;

    # maybestarttls fails closed when STARTTLS is advertised but the handshake
    # does not complete, which a relay with a self signed certificate does
    # every time. Cleartext last is what opportunistic delivery means
    # (RFC 7435): the alternative is not TLS, it is the report being dropped.
    # Credentials never reach here, and never get maybestarttls either, which
    # authenticates over plaintext when STARTTLS is not advertised.
    return (
        $self->smarthost_route( \%common, {}, 25, 'maybestarttls' ),
        $self->smarthost_route( \%common, {}, 587, 'starttls' ),
        $self->smarthost_route( \%common, {}, 25, 0 ),
    );
}

sub smarthost_route( $self, $common, $auth, $port, $ssl ) {
    return Email::Sender::Transport::SMTP::Persistent->new(
        { %$common, %$auth, port => $port, ssl => $ssl } );
}

sub smarthost_ssl_configured( $self, $report ) {
    my $ssl = $report->config->{smtp}{smartssl};
    return defined $ssl && $ssl =~ /\S/x ? 1 : 0;
}

sub smarthost_ssl( $self, $report ) {
    my $ssl = lc $report->config->{smtp}{smartssl};
    $ssl =~ s/\A\s+|\s+\z//gx;

    croak "unknown smtp.smartssl '$ssl', expected one of: none, "
        . join( ', ', sort keys %SMART_SSL )
        if 'none' ne $ssl && !$SMART_SSL{$ssl};

    return 0 if 'none' eq $ssl;
    return $ssl;
}

sub builds_smarthost_routes( $self, $report ) {
    return 0 if $self->{transports_method} || $self->{transports_object};
    return 0 if $self->{smarthost};
    return $report->config->{smtp}{smarthost} ? 1 : 0;
}

# A route that never answers costs a connect timeout on every message.
sub keep_smarthost_route( $self, $transport ) {
    return if 'ARRAY' ne ref $self->{smarthost};
    return if !grep { refaddr($_) == refaddr($transport) } @{ $self->{smarthost} };
    $self->{smarthost} = [$transport];
    return;
}

# Return a list of transports to try in order.
sub get_transports_for( $self, $args ) {

    # Have we passed a custom transports generation class?
    if ( $self->{transports_method} ) {
        my @transports = &{ $self->{transports_method} }($args);
        return @transports;
    }
    if ( $self->{transports_object} ) {
        my @transports = $self->{transports_object}->get_transports_for($args);
        return @transports;
    }

    my $report = $args->{report};

    if ( $report->config->{smtp}{smarthost} ) {
        return @{ $self->{smarthost} } if 'ARRAY' eq ref $self->{smarthost};
        return ( $self->{smarthost} )   if $self->{smarthost};
        $self->{smarthost} = [ $self->smarthost_transports($report) ];
        return @{ $self->{smarthost} };
    }

    my @smtp_hosts = $report->sendit->smtp->get_smtp_hosts( $args->{to} );

    my $log_data = $args->{log_data};
    $log_data->{smtp_host} = join( ',', @smtp_hosts );

    my %common = (
        port    => 25,
        helo    => $report->sendit->smtp->get_helo_hostname,
        timeout => 32,
    );

    # Every MX is tried encrypted before any is tried in the clear. A receiver
    # whose certificate cannot be verified still fails the handshake closed,
    # and its reports would otherwise be dropped undelivered.
    if ( Email::Sender::Transport::SMTP->can('hosts') ) {
        return map {
            Email::Sender::Transport::SMTP->new(
                { %common, hosts => \@smtp_hosts, ssl => $_ } )
        } ( 'maybestarttls', 0 );
    }

    # Older transports take one host, so each MX needs its own.
    my @transports;
    foreach my $ssl ( 'maybestarttls', 0 ) {
        push @transports,
            Email::Sender::Transport::SMTP->new(
            { %common, host => $_, ssl => $ssl } )
            foreach @smtp_hosts;
    }

    return @transports;
}

sub get_dkim_key($self) {
    my $report = $self->{report};
    return $self->{dkim_key} if $self->{dkim_key};
    if ( $report->config->{report_sign}->{keyfile} ) {
        try {
            require Mail::DKIM::PrivateKey;
            require Mail::DKIM::Signer;
            require Mail::DKIM::TextWrap;
        } catch ($e) { };
        if ( UNIVERSAL::can( 'Mail::DKIM::Signer', "new" ) ) {
            my $file = $report->config->{report_sign}->{keyfile};
            $self->{dkim_key} = Mail::DKIM::PrivateKey->load( 'File' => $file, );
            if ( !$self->{dkim_key} ) {
                die "Could not load DKIM key $file";
            }
        }
        else {
            die
                'DKIM signing requested but Mail::DKIM could not be loaded. Please check that Mail::DKIM is installed.';
        }
        $self->log_output('DKIM signing key loaded');
        return $self->{dkim_key};
    }
}

sub run($self) {

    GetOptions(
        'verbose+'  => \$self->{verbose},
        'delay=i'   => \$self->{send_delay},
        'batch=i'   => \$self->{batch_size},
        'timeout=i' => \$self->{alarm_at},
        'syslog+'   => \$self->{syslog},
    );

    openlog( 'dmarc_send_reports', 'pid', LOG_MAIL ) if $self->{syslog};
    $self->log_output('dmarc_send_reports starting up');

    $|++;
    my $report = Mail::DMARC::Report->new();
    $self->{report} = $report;
    $report->verbose( $self->{verbose} ) if defined $self->{verbose};

    # If we have defined a custom transports generation class then
    # load and instantiate it here.
    if ( $report->config->{smtp}->{transports} ) {
        load $report->config->{smtp}->{transports};
        my $package           = $report->config->{smtp}->{transports};
        my $transports_object = $package->new();
        $self->set_transports_object($transports_object);
    }

    $self->smarthost_ssl($report)
        if $self->builds_smarthost_routes($report)
        && $self->smarthost_ssl_configured($report);

    local $SIG{'ALRM'} = sub { die "timeout\n" };

    my $batch_do = 1;

    # 1. get reports, one at a time
REPORT:
    while ( my $aggregate = $report->store->next_todo() ) {
        try {
            $self->send_report( $aggregate, $report );
        }
        catch ($error) {
            $self->log_output( 'error sending report: ' . $error );
        }

        if ( $batch_do++ > $self->{batch_size} ) {
            $batch_do = 1;
            if ( $self->{send_delay} > 0 ) {
                print "sleeping " . $self->{send_delay} if $self->{verbose};
                foreach ( 1 .. $self->{send_delay} ) {
                    print '.' if $self->{verbose};
                    sleep 1;
                }
                print "done.\n" if $self->{verbose};
            }
        }

    }

    alarm(0);

    $self->log_output('dmarc_send_reports done');
    closelog() if $self->{syslog};

    return;
}

# PODNAME: dmarc_send_reports
# ABSTRACT: send aggregate reports

sub send_report( $self, $aggregate, $report ) {

    alarm( $self->{alarm_at} );

    $self->log_output(
        {   'id'     => $aggregate->metadata->report_id,
            'domain' => $aggregate->policy_published->domain,
            'rua'    => $aggregate->policy_published->rua,
        }
    );

    # Generate the list of report receivers
    my $report_receivers;
    try {
        $report_receivers = $report->uri->parse( $aggregate->policy_published->rua );
    }
    catch ($error) {
        $self->log_output(
            {   'id'    => $aggregate->metadata->report_id,
                'error' => 'No valid ruas found - deleting report - ' . $error,
            }
        );
        $report->store->delete_report( $aggregate->metadata->report_id );
        alarm(0);
        return;
    }

    # Check we have some receivers
    if ( !@$report_receivers ) {
        $self->log_output(
            {   'id'    => $aggregate->metadata->report_id,
                'error' => 'No valid ruas found - deleting report',
            }
        );
        $report->store->delete_report( $aggregate->metadata->report_id );
        alarm(0);
        return;
    }

    # Generate the XML data and associated metadata
    my $xml                  = $aggregate->as_xml();
    my $xml_compressed       = $report->compress( \$xml );
    my $xml_compressed_bytes = length Encode::encode_utf8($xml_compressed);

    my $sent    = 0;
    my $cc_sent = 0;
    my @too_big;
URI:
    foreach my $receiver (@$report_receivers) {
        my $method = $receiver->{uri};
        my $max    = $receiver->{max_bytes};

        if ( $max && $xml_compressed_bytes > $max ) {
            $self->log_output(
                {   'id'   => $aggregate->metadata->report_id,
                    'info' =>
                        "skipping $method: report size ($xml_compressed_bytes) larger than $max",
                }
            );
            push @too_big, $method;
            next URI;
        }
        elsif ( 'mailto:' eq substr( $method, 0, 7 ) ) {
            my ($to) = ( split /:/, $method )[-1];
            my $cc = $report->config->{smtp}{cc};
            if ( $cc && $cc ne 'set.this@for.a.while.example.com' && !$cc_sent ) {
                $self->email(
                    {   to         => $cc,
                        compressed => $xml_compressed,
                        aggregate  => \$aggregate
                    }
                );
                $cc_sent = 1;
            }
            $self->email(
                {   to         => $to,
                    compressed => $xml_compressed,
                    aggregate  => \$aggregate
                }
            ) and $sent++;
        }

        # http(s) sending not yet enabled in module, skip this send and
        # increment sent to avoid looping
        elsif ( 'http:' eq substr( $method, 0, 5 ) ) {

            #$report->sendit->http->post( $method, \$aggregate, $shrunk );
            $sent++;
        }
        elsif ( 'https:' eq substr( $method, 0, 6 ) ) {

            #$report->sendit->http->post( $method, \$aggregate, $shrunk );
            $sent++;
        }
    }

    if ($sent) {
        $report->store->delete_report( $aggregate->metadata->report_id );
    }
    else {
        my $send_errors = $report->config->{smtp}->{send_errors} // 1;
        $self->send_too_big_email( \@too_big, $xml_compressed_bytes, $aggregate )
            if $send_errors;
        $report->store->delete_report( $aggregate->metadata->report_id );
    }

    alarm(0);
    return;
}

sub send_too_big_email( $self, $too_big, $bytes, $aggregate ) {
    my $report = $self->{report};

BIGURI:
    foreach my $uri (@$too_big) {
        next BIGURI if 'mailto:' ne substr( $uri, 0, 7 );
        my ($to) = ( split /:/, $uri )[-1];
        my $body = $report->sendit->too_big_report(
            {   uri           => $uri,
                report_bytes  => $bytes,
                report_id     => $aggregate->metadata->report_id,
                report_domain => $aggregate->policy_published->domain,
            }
        );
        my $mime_object
            = $report->sendit->smtp->assemble_too_big_message_object( $to, $body );
        $self->email( { to => $to, mime => $mime_object } );
    }
    return;
}

sub email( $self, $args ) {

    my $to = $args->{to};
    if ( !$to ) {
        $self->log_output( { 'error' => 'No recipient for email' } );
        croak 'No recipient for email';
    }
    my $mime       = $args->{mime}       // undef;
    my $compressed = $args->{compressed} // undef;
    my $agg_ref    = $args->{aggregate}  // undef;
    my $report     = $self->{report};

    my $rid;
    $rid = $$agg_ref->metadata->report_id if $agg_ref;

    my $log_data = { deliver_to => $to, };

    my $body;
    if ($rid) {
        my $mime_object
            = $report->sendit->smtp->assemble_message_object( $agg_ref, $to,
            $compressed );
        $body                  = $mime_object->as_string;
        $log_data->{id}        = $rid;
        $log_data->{to_domain} = $$agg_ref->policy_published->domain;
    }
    elsif ($mime) {
        $body = $mime->as_string;
    }
    else {
        croak 'No email content';
    }

    my $dkim_key = $self->get_dkim_key();
    if ($dkim_key) {
        my $dkim_algorithm = $report->config->{report_sign}{algorithm};
        my $dkim_method    = $report->config->{report_sign}{method};
        my $dkim_domain    = $report->config->{report_sign}{domain};
        my $dkim_selector  = $report->config->{report_sign}{selector};
        try {
            my $dkim = Mail::DKIM::Signer->new(
                Algorithm => $dkim_algorithm,
                Method    => $dkim_method,
                Domain    => $dkim_domain,
                Selector  => $dkim_selector,
                Key       => $dkim_key,
            );
            $body =~ s/\015?\012/\015\012/g;
            $dkim->PRINT($body);
            $dkim->CLOSE;
            my $signature = $dkim->signature;
            $body = $signature->as_string . "\015\012" . $body;
            $log_data->{dkim} = 1;
        }
        catch ($error) {
            print "DKIM Signing error\n\t$error\n" if $self->{verbose};
            $log_data->{error}        = 'DKIM Signing error';
            $log_data->{error_detail} = $error;
            $self->log_output($log_data);
            return;
        }
    }

    my @transports = $self->get_transports_for(
        {   report   => $report,
            log_data => $log_data,
            to       => $to,
        }
    );
    my $success;
    my $permanent = 0;
    my $answered  = 0;
    while ( my $transport = shift @transports ) {

        # A cleartext retry is for a handshake that never completed. Once a
        # host has answered in SMTP it has seen the session, and repeating it
        # unencrypted would put the report on the wire for a greylisting or a
        # content rejection.
        next if $answered && $transport->can('ssl') && !$transport->ssl;

        my $done = 0;
        try {
            $success = sendmail(
                $body,
                {   from      => $report->config->{organization}{email},
                    to        => $to,
                    transport => $transport,
                }
            );
            if ($success) {
                $log_data->{success} = $success->{message};
                $done = 1;
                $self->keep_smarthost_route($transport);
            }
        }
        catch ($error) {
            my $code;
            my $message;

            # A connect, TLS or AUTH failure arrives as a plain string, and
            # ->code on that threw past the code that retires the report.
            if ( blessed($error) && $error->isa('Email::Sender::Failure') ) {
                $code    = $error->code;
                $message = $error->message;
            }
            else {
                $code    = 'error';
                $message = "$error";
                chomp $message;
            }
            $code    //= 'error';
            $message //= 'unknown send failure';

            # Connect and STARTTLS failures carry no code; anything else means
            # the host answered.
            $answered ||= $code ne 'error';

            # Any rung answering 5xx settles the report: the host has refused
            # it, and the rungs are ports on that same host.
            $permanent ||= $code =~ /^5/x;

            my $timed_out = 'timeout' eq $message;

            $code = join( ', ', $log_data->{send_error_code}, $code )
                if exists $log_data->{send_error_code};
            $message = join( ', ', $log_data->{send_error}, $message )
                if exists $log_data->{send_error};
            $log_data->{send_error}      = $message;
            $log_data->{send_error_code} = $code;

            # The alarm in send_report bounds the report, not each rung, and
            # is not rearmed; carrying on would leave the ladder unbounded and
            # could resend a message the server already took.
            if ($timed_out) {
                $report->store->error( $rid, $message );
                last;
            }

            next if @transports;

            if ($permanent) {

                # Perma error
                $log_data->{deleted} = 1;
                $report->store->delete_report($rid);
                $success = 0;
                last;
            }
            $report->store->error( $rid, $message );
        }
        last if $done;
    }

    $self->log_output($log_data);

    if ($success) {
        return 1;
    }
    return 0;
}

sub log_output( $self, $args ) {

    my $log_level = LOG_INFO;
    my $log_entry = '';

    if ( ref $args eq 'HASH' ) {

        if ( $args->{'log_level'} ) {
            $log_level = $args->{'log_level'};
            delete $args->{'log_level'};
        }

        my @parts;
        foreach my $key ( sort keys %$args ) {
            my $value = $args->{$key} // '';
            $value =~ s/,/#044/g;    # Encode commas
            push @parts, join( '=', $key, $value );
        }
        $log_entry = join( ', ', @parts );
    }
    else {
        $log_entry = $args;
    }

    syslog( $log_level, $log_entry ) if $self->{syslog};
    print "$log_entry\n"             if $self->{verbose};

    return;
}

1;
