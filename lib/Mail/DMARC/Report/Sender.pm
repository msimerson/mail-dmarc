package Mail::DMARC::Report::Sender;

use strict;
use warnings;

use Data::Dumper;
use Carp;
use Encode;
use Getopt::Long;
use Sys::Syslog qw(:standard :macros);
use Mail::DMARC::Report;
use Email::Sender::Simple qw{ sendmail };
use Email::Sender::Transport::SMTP;
use Email::Sender::Transport::SMTP::Persistent;
use Module::Load;

sub new {
    my $class = shift;
    my $self = {
        send_delay => 5,
        batch_size => 1,
        alarm_at => 120,
        syslog => 0,
        smarthost => undef,
        transports_method => undef,
        transports_object => undef,
        dkim_key => undef,
        verbose => 0,
    };
    return bless $self, $class;
};

sub set_transports_object {
    my ( $self,$transports_object ) = @_;
    $self->{transports_object} = $transports_object;
    return;
}

sub set_transports_method {
    my ( $self,$transports_method ) = @_;
    $self->{transports_method} = $transports_method;
    return;
    # Transports method is a sub which returns
    # a list of transports for the given args.
}

# Return a list of transports to try in order.
sub get_transports_for {
    my ( $self, $args ) = @_;
    # Have we passed a custom transports generation class?
    if ( $self->{transports_method} ) {
        my @transports = &{$self->{transports_method}}( $args );
        return @transports;
    }
    if ( $self->{transports_object} ) {
        my @transports = $self->{transports_object}->get_transports_for( $args );
        return @transports;
    }

    my $report = $args->{report};

    # Do we have a smart host?
    if ( $report->config->{smtp}{smarthost} ) {
        return ($self->{smarthost}) if $self->{smarthost};
        my $transport_data = {
            host => $report->config->{smtp}->{smarthost},
            ssl => 1,
            port => 587,
            helo => $report->sendit->smtp->get_helo_hostname,
            timeout => 32,
        };
        $transport_data->{sasl_username} = $report->config->{smtp}->{smartuser} if $report->config->{smtp}->{smartuser};
        $transport_data->{sasl_password} = $report->config->{smtp}->{smartpass} if $report->config->{smtp}->{smartpass};
        my $transport = Email::Sender::Transport::SMTP::Persistent->new($transport_data);
        $self->{smarthost} = $transport;
        return ($self->{smarthost});
    }

    my @smtp_hosts = $report->sendit->smtp->get_smtp_hosts($args->{to});

    my $log_data = $args->{log_data};
    my @transports;
    $log_data->{smtp_host} = join( ',', @smtp_hosts );

    if ( Email::Sender::Transport::SMTP->can('hosts') ) {
        push @transports, Email::Sender::Transport::SMTP->new({
            hosts => \@smtp_hosts,
            ssl => 1,
            port => 25,
            helo => $report->sendit->smtp->get_helo_hostname,
            timeout => 32,
        });
        push @transports, Email::Sender::Transport::SMTP->new({
            hosts => \@smtp_hosts,
            ssl => 0,
            port => 25,
            helo => $report->sendit->smtp->get_helo_hostname,
            timeout => 32,
        });
    }
    else {
        # We can't pass hosts to the transport, so pass a list of transports
        # for each possible host.

        foreach my $host ( @smtp_hosts ) {
            push @transports, Email::Sender::Transport::SMTP->new({
                host => $host,
                ssl => 1,
                port => 25,
                helo => $report->sendit->smtp->get_helo_hostname,
                timeout => 32,
            });
        }
        foreach my $host ( @smtp_hosts ) {
            push @transports, Email::Sender::Transport::SMTP->new({
                host => $host,
                ssl => 0,
                port => 25,
                helo => $report->sendit->smtp->get_helo_hostname,
                timeout => 32,
            });
        }
    }

    return @transports;
}

sub get_dkim_key {
    my ( $self ) = @_;
    my $report = $self->{report};
    return $self->{dkim_key} if $self->{dkim_key};
    if ( $report->config->{report_sign}->{keyfile} ) {
        eval {
            require Mail::DKIM::PrivateKey;
            require Mail::DKIM::Signer;
            require Mail::DKIM::TextWrap;
        };
        if ( UNIVERSAL::can( 'Mail::DKIM::Signer', "new" ) ) {
            my $file = $report->config->{report_sign}->{keyfile};
            $self->{dkim_key} = Mail::DKIM::PrivateKey->load(
                'File' => $file,
            );
            if ( ! $self->{dkim_key} ) {
                die "Could not load DKIM key $file";
            }
        }
        else {
            die 'DKIM signing requested but Mail::DKIM could not be loaded. Please check that Mail::DKIM is installed.';
        }
        $self->log_output( 'DKIM signing key loaded' );
        return $self->{dkim_key};
    }
}


sub run {
    my ( $self ) = @_;

    GetOptions (
        'verbose+'   => \$self->{verbose},
        'delay=i'    => \$self->{send_delay},
        'batch=i'    => \$self->{batch_size},
        'timeout=i'  => \$self->{alarm_at},
        'syslog+'    => \$self->{syslog},
    );

    openlog( 'dmarc_send_reports', 'pid', LOG_MAIL )     if $self->{syslog};
    $self->log_output( 'dmarc_send_reports starting up' );

    $|++;
    my $report = Mail::DMARC::Report->new();
    $self->{report} = $report;
    $report->verbose($self->{verbose}) if defined $self->{verbose};
    # If we have defined a custom transports generation class then
    # load and instantiate it here.
    if ( $report->config->{smtp}->{transports} ) {
        load $report->config->{smtp}->{transports};
        my $package = $report->config->{smtp}->{transports};
        my $transports_object = $package->new();
        $self->set_transports_object( $transports_object );
    }

    local $SIG{'ALRM'} = sub{ die "timeout\n" };

    my $batch_do = 1;

    # 1. get reports, one at a time
    REPORT:
    while ( my $aggregate = $report->store->next_todo() ) {
        eval {
            $self->send_report( $aggregate, $report );
        };
        if ( my $error = $@ ) {
            $self->log_output( 'error sending report: ' . $error );
        }

        if ( $batch_do++ > $self->{batch_size} ) {
            $batch_do = 1;
            if ( $self->{send_delay} > 0 ) {
                print "sleeping ".$self->{send_delay} if $self->{verbose};
                foreach ( 1 .. $self->{send_delay} ) { print '.' if $self->{verbose}; sleep 1; };
                print "done.\n" if $self->{verbose};
            }
        }

    }

    alarm(0);

    $self->log_output( 'dmarc_send_reports done' );
    closelog() if $self->{syslog};

    return;
}

# PODNAME: dmarc_send_reports
# ABSTRACT: send aggregate reports

sub send_report {

    my ( $self, $aggregate, $report ) = @_;

    alarm($self->{alarm_at});

    $self->log_output({
        'id'     => $aggregate->metadata->report_id,
        'domain' => $aggregate->policy_published->domain,
        'rua'    => $aggregate->policy_published->rua,
    });

    # Generate the list of report receivers
    my $report_receivers = eval{ $report->uri->parse( $aggregate->policy_published->rua ) };
    if ( my $error = $@ ) {
        $self->log_output({
            'id'    =>  $aggregate->metadata->report_id,
            'error' => 'No valid ruas found - deleting report - ' . $error,
        });
        $report->store->delete_report($aggregate->metadata->report_id);
        alarm(0);
        return;
    }

    # Check we have some receivers
    if ( scalar @$report_receivers == 0 ) {
        $self->log_output({
            'id'    =>  $aggregate->metadata->report_id,
            'error' => 'No valid ruas found - deleting report',
        });
        $report->store->delete_report($aggregate->metadata->report_id);
        alarm(0);
        return;
    }

    # Generate the XML data and associated metadata
    my $xml = $aggregate->as_xml();
    my $xml_compressed = $report->compress(\$xml);
    my $xml_compressed_bytes  = length Encode::encode_utf8($xml_compressed);

    my $sent    = 0;
    my $cc_sent = 0;
    my @too_big;
    URI:
    foreach my $receiver (@$report_receivers) {
        my $method = $receiver->{uri};
        my $max    = $receiver->{max_bytes};

        if ( $max && $xml_compressed_bytes > $max ) {
           $self->log_output({
                'id'   => $aggregate->metadata->report_id,
                "info' => 'skipping $method: report size ($xml_compressed_bytes) larger than $max",
            });
            push @too_big, $method;
            next URI;
        }
        elsif ( 'mailto:' eq substr( $method, 0, 7 ) ) {
            my ($to) = ( split /:/, $method )[-1];
            my $cc = $report->config->{smtp}{cc};
            if ( $cc && $cc ne 'set.this@for.a.while.example.com' && ! $cc_sent ) {
                $self->email({ to => $cc, compressed => $xml_compressed, aggregate => \$aggregate });
                $cc_sent = 1;
            };
            $self->email({ to => $to, compressed => $xml_compressed, aggregate => \$aggregate }) and $sent++;
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

    if ( $sent ) {
        $report->store->delete_report($aggregate->metadata->report_id);
    }
    else {
        $self->send_too_big_email(\@too_big, $xml_compressed_bytes, $aggregate);
    };

    alarm(0);
    return;
}

sub send_too_big_email {
    my ($self, $too_big, $bytes, $aggregate) = @_;
    my $report = $self->{report};

    BIGURI:
    foreach my $uri (@$too_big) {
        next BIGURI if 'mailto:' ne substr( $uri, 0, 7 );
        my ($to) = ( split /:/, $uri )[-1];
        my $body = $report->sendit->too_big_report(
            {   uri          => $uri,
                report_bytes => $bytes,
                report_id    => $aggregate->metadata->report_id,
                report_domain=> $aggregate->policy_published->domain,
            }
        );
        my $mime_object = $report->sendit->smtp->assemble_too_big_message_object($aggregate, $to, $body);
        $self->email({ to => $to, mime => $mime_object });
    };
    return;
};

sub email {
    my ($self, $args) = @_;

    my $to = $args->{to};
    if ( !$to ) {
        $self->log_output({ 'error' => 'No recipient for email' });
        croak 'No recipient for email';
    }
    my $mime = $args->{mime} // undef;
    my $compressed = $args->{compressed} // undef;
    my $agg_ref = $args->{aggregate} // undef;
    my $report = $self->{report};

    my $rid;
    $rid = $$agg_ref->metadata->report_id if $agg_ref;

    my $log_data = {
        deliver_to => $to,
    };

    my $body;
    if ( $rid ) {
        my $mime_object = $report->sendit->smtp->assemble_message_object($agg_ref, $to, $compressed);
        $body = $mime_object->as_string;
        $log_data->{id} = $rid;
        $log_data->{to_domain} = $$agg_ref->policy_published->domain;
    }
    elsif ( $mime ) {
        $body = $mime->as_string;
    }
    else {
        croak 'No email content';
    }

    my $dkim_key = $self->get_dkim_key();
    if ( $dkim_key ) {
        my $dkim_algorithm = $report->config->{report_sign}{algorithm};
        my $dkim_method    = $report->config->{report_sign}{method};
        my $dkim_domain    = $report->config->{report_sign}{domain};
        my $dkim_selector  = $report->config->{report_sign}{selector};
        eval {
            my $dkim = Mail::DKIM::Signer->new(
                Algorithm => $dkim_algorithm,
                Method    => $dkim_method,
                Domain    => $dkim_domain,
                Selector  => $dkim_selector,
                Key       => $dkim_key,
            );
            $body =~ s/\015?\012/\015\012/g;
            $dkim->PRINT( $body );
            $dkim->CLOSE;
            my $signature = $dkim->signature;
            $body = $signature->as_string . "\015\012" . $body;
            $log_data->{dkim} = 1;
        };
        if ( my $error = $@ ) {
            print "DKIM Signing error\n\t$error\n" if $self->{verbose};
            $log_data->{error} = 'DKIM Signing error';
            $log_data->{error_detail} = $error;
            $self->log_output($log_data);
            return;
        }
    }

    my @transports = $self->get_transports_for({
        report => $report,
        log_data => $log_data,
        to => $to,
    });
    my $success;
    while ( my $transport = shift @transports ) {
        my $done = 0;
        eval {
            $success = sendmail(
                $body,
                {
                    from => $report->config->{organization}{email},
                    to => $to,
                    transport => $transport,
                }
            );
            if ( $success ) {
                $log_data->{success} = $success->{message};
                $done = 1;
            }
        };
        if ( my $error = $@ ) {
            next if scalar @transports;
            my $code = $error->code;
            my $message = $error->message;
            $code = join( ', ', $log_data->{send_error_code}, $code ) if exists $log_data->{send_error_code};
            $message = join( ', ', $log_data->{send_error}, $message ) if exists $log_data->{send_error};
            $log_data->{send_error} = $message;
            $log_data->{send_error_code} = $code;
            if ( $error->code && $error->code =~ /^5/ ) {
                # Perma error
                $log_data->{deleted} = 1;
                $report->store->delete_report($rid);
                $success = 0;
                last;
            }
            $report->store->error($rid, $error->message);
        }
        last if $done;
    }

    $self->log_output( $log_data );

    if ( $success ) {
        return 1;
    }
    return 0;
}

sub log_output {
    my ( $self, $args ) = @_;

    my $log_level = LOG_INFO;
    my $log_entry = '';

    if ( ref $args eq 'HASH' ) {

        if ( $args->{'log_level'} ) {
            $log_level = $args->{'log_level'};
            delete $args->{'log_level'};
        }

        my @parts;
        foreach my $key ( sort keys %$args ) {
            my $value = $args->{ $key };
            $value =~ s/,/#044/g; # Encode commas
            push @parts, join( '=', $key, $value );
        }
        $log_entry =  join( ', ', @parts );
    }
    else {
        $log_entry = $args;
    }

    syslog( $log_level, $log_entry ) if $self->{syslog};
    print "$log_entry\n"             if $self->{verbose};

    return;
}

1;
