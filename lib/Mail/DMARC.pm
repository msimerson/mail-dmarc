package Mail::DMARC;
use strict;
use warnings;

our $VERSION = '1.20240313';

use Carp;
our $psl_loads = 0;

use parent 'Mail::DMARC::Base';
require Mail::DMARC::Policy;
require Mail::DMARC::Report;
require Mail::DMARC::Result;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
require Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;

sub new {
    my ( $class, @args ) = @_;
    croak "invalid args" if scalar @args % 2;
    my %args = @args;
    my $self = bless {
        config_file => 'mail-dmarc.ini',
        }, $class;

    my @keys = sort { $a eq 'config_file' ? -1
                    : $b eq 'config_file' ?  1
                    : ($a cmp $b) } keys %args;

    foreach my $key ( @keys ) {
        if ($self->can($key)) {
            $self->$key( $args{$key} );
        }
        else {
            $self->{$key} = $args{$key};
        }
    }
    return $self;
}

sub source_ip {
    return $_[0]->{source_ip} if 1 == scalar @_;
    croak "invalid source_ip" if !$_[0]->is_valid_ip( $_[1] );
    return $_[0]->{source_ip} = $_[1];
}

sub envelope_to {
    return $_[0]->{envelope_to} if 1 == scalar @_;
    croak "invalid envelope_to" if !$_[0]->is_valid_domain( $_[1] );
    return $_[0]->{envelope_to} = $_[1];
}

sub envelope_from {
    return $_[0]->{envelope_from} if 1 == scalar @_;
    croak "invalid envelope_from" if !$_[0]->is_valid_domain( $_[1] );
    return $_[0]->{envelope_from} = $_[1];
}

sub header_from {
    return $_[0]->{header_from} if 1 == scalar @_;
    croak "invalid header_from" if !$_[0]->is_valid_domain( $_[1] );
    return $_[0]->{header_from} = lc $_[1];
}

sub header_from_raw {
    return $_[0]->{header_from_raw} if 1 == scalar @_;
#croak "invalid header_from_raw: $_[1]" if 'from:' ne lc substr($_[1], 0, 5);
    return $_[0]->{header_from_raw} = lc $_[1];
}

sub local_policy {
    return $_[0]->{local_policy} if 1 == scalar @_;

    # TODO: document this, when and why it would be used
    return $_[0]->{local_policy} = $_[1];
}

sub dkim {
    my ($self, @args) = @_;

    if (0 == scalar @args) {
        $self->_unwrap('dkim');
        return $self->{dkim};
    }

    # one shot
    if (1 == scalar @args) {
        # warn "one argument\n";
        if (ref $args[0] eq 'CODE') {
            return $self->{dkim} = $args[0];
        }

        if ( ref $args[0] eq 'ARRAY') {
            foreach my $d ( @{ $args[0] }) {
                push @{ $self->{dkim}},
                    Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new($d);
            }
            return $self->{dkim};
        }

        if ( ref $args[0] eq 'Mail::DKIM::Verifier' ) {
            $self->_from_mail_dkim($args[0]);
            return $self->{dkim};
        }
    };

    #warn "iterative\n";
    push @{ $self->{dkim}},
        Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(@args);

    return $self->{dkim};
}

sub _from_mail_dkim {
    my ( $self, $dkim ) = @_;

    my $signatures = 0;

    # A DKIM verifier will have result and signature methods.
    foreach my $s ( $dkim->signatures ) {
        next if ref $s eq 'Mail::DKIM::DkSignature';
        $signatures++;

        my $result = $s->result;

        if ($result eq 'invalid') {  # See GH Issue #21
            $result = 'temperror';
        }

        push @{ $self->{dkim}},
            Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(
                domain       => $s->domain,
                selector     => $s->selector,
                result       => $result,
                human_result => $s->result_detail,
            );
    }

    if ($signatures < 1) {
        push @{ $self->{dkim}},
            Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM->new(
                domain       => '',
                result       => 'none',
            );
    }

    return;
}

sub _unwrap {
    my ( $self, $key ) = @_;
    if ($self->{$key} and ref $self->{$key} eq 'CODE') {
        my $code = delete $self->{$key};
        $self->$key( $self->$code );
    }
    return;
}

sub spf {
   my ($self, @args) = @_;
    if (0 == scalar @args) {
      $self->_unwrap('spf');
      return $self->{spf};
    }

    if (1 == scalar @args && ref $args[0] eq 'CODE') {
      return $self->{spf} = $args[0];
    }

    if (1 == scalar @args && ref $args[0] eq 'ARRAY') {
        # warn "SPF one shot";
        foreach my $d ( @{ $args[0] }) {
            push @{ $self->{spf} },
                Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new($d);
        }
        return $self->{spf};
    }

    #warn "SPF iterative";
    push @{ $self->{spf} },
        Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF->new(@args);

    return $self->{spf};
}

sub policy {
    my ( $self, @args ) = @_;
    return $self->{policy} if ref $self->{policy} && 0 == scalar @args;
    return $self->{policy} = Mail::DMARC::Policy->new(@args);
}

sub report {
    my $self = shift;
    return $self->{report} if ref $self->{report};
    return $self->{report} = Mail::DMARC::Report->new();
}

sub result {
    my $self = shift;
    return $self->{result} if ref $self->{result};
    return $self->{result} = Mail::DMARC::Result->new();
}

sub is_subdomain {
    return $_[0]->{is_subdomain} if 1 == scalar @_;
    croak "invalid boolean" if 0 == grep {/^$_[1]$/ix} qw/ 0 1/;
    return $_[0]->{is_subdomain} = $_[1];
}

sub get_report_window {
    my ( $self, $interval, $now ) = @_;

    my $min_interval = $self->config->{'report_sending'}{'min_interval'};
    my $max_interval = $self->config->{'report_sending'}{'max_interval'};

    $interval = 86400 if ! $interval; # Default to 1 day
    if ( $min_interval ) {
        $interval = $min_interval if $interval < $min_interval;
    }
    if ( $max_interval ) {
        $interval = $max_interval if $interval > $max_interval;
    }

    if ( ( 86400 % $interval ) != 0 ) {
        # Interval does not fit into a day nicely,
        # So don't work out a window, just run with it.
        return ( $now, $now + $interval - 1);
    }

    my $begin = $self->get_start_of_zulu_day( $now );
    my $end = $begin + $interval - 1;

    while ( $end < $now ) {
        $begin = $begin + $interval;
        $end   = $begin + $interval - 1;
    }

    return ( $begin, $end );
}


sub get_start_of_zulu_day {
    my ( $self, $t ) = @_;
    my $start_of_zulu_day = $t - ( $t % 86400 );
    return $start_of_zulu_day;
}

sub save_aggregate {
    my ($self) = @_;

    my $agg = $self->report->aggregate;

    # put config information in report metadata
    foreach my $f ( qw/ org_name email extra_contact_info report_id / ) {
        $agg->metadata->$f( $self->config->{organization}{$f} );
    };

    my ( $begin, $end ) = $self->get_report_window( $self->result->published->ri, $self->time );

    $agg->metadata->begin( $begin );
    $agg->metadata->end( $end );

    $agg->policy_published( $self->result->published );

    my $rec = Mail::DMARC::Report::Aggregate::Record->new();
    $rec->row->source_ip( $self->source_ip );

    $rec->identifiers(
            envelope_to   => $self->envelope_to,
            envelope_from => $self->envelope_from,
            header_from   => $self->header_from,
        );

    $rec->auth_results->dkim($self->dkim);
    $rec->auth_results->spf($self->spf);

    $rec->row->policy_evaluated(
        disposition   => $self->result->disposition,
        dkim          => $self->result->dkim,
        spf           => $self->result->spf,
        reason        => $self->result->reason,
    );

    $agg->record($rec);
    return $self->report->save_aggregate;
}

sub init {
    # used for testing
    my $self = shift;
    map { delete $self->{$_} } qw/ spf spf_ar dkim dkim_ar /;
    return;
}

1;

__END__

=pod

=head1 Status Badges

=for markdown [![Build Status](https://github.com/msimerson/mail-dmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/msimerson/mail-dmarc/actions/workflows/ci.yml)

=for markdown [![Coverage Status](https://coveralls.io/repos/msimerson/mail-dmarc/badge.svg)](https://coveralls.io/r/msimerson/mail-dmarc)

=head1 NAME

Mail::DMARC - Perl implementation of DMARC

=head1 VERSION

version 1.20240313

=head1 SYNOPSIS

DMARC: Domain-based Message Authentication, Reporting and Conformance

  my $dmarc = Mail::DMARC::PurePerl->new(
    ... # see the documentation for the "new" method for required args
  );

  my $result = $dmarc->validate();

  if ( $result->result eq 'pass' ) {
     ...continue normal processing...
     return;
  };

  # any result that did not pass is a fail. Now for disposition

  if ( $result->evalated->disposition eq 'reject' ) {
     ...treat the sender to a 550 ...
  };
  if ( $result->evalated->disposition eq 'quarantine' ) {
     ...assign a bunch of spam points...
  };
  if ( $result->evalated->disposition eq 'none' ) {
     ...continue normal processing...
  };

=head1 DESCRIPTION

This module is a suite of tools for implementing DMARC. It adheres to the 2013 DMARC draft, intending to implement every MUST and every SHOULD.

This module can be used by...

=over 4

=item *

MTAs and filtering tools like SpamAssassin to validate that incoming messages are aligned with the purported sender's policy.

=item *

email senders, to receive DMARC reports from other mail servers and display them via CLI and web interfaces.

=item *

MTA operators to send DMARC reports to DMARC author domains.

=back

When a message arrives via SMTP, the MTA or filtering application can pass in a small amount of metadata about the connection (envelope details, SPF and DKIM results) to Mail::DMARC. When the B<validate> method is called, Mail::DMARC will determine if:

 a. the header_from domain exists
 b. the header_from domain publishes a DMARC policy
 c. if a policy is published...
 d. does the message conform to the published policy?
 e. did the policy request reporting? If so, save details.

The validation results are returned as a L<Mail::DMARC::Result> object. If the author domain requested a report, it was saved to the L<Report Store|Mail::DMARC::Report::Store>. The Store class includes a SQL implementation that is tested with SQLite, MySQL and PostgreSQL.

There is more information available in the $result object. See L<Mail::DMARC::Result> for complete details.

Reports are viewed with the L<dmarc_view_reports> program or with a web browser and the L<dmarc_httpd> program.

Aggregate reports are sent to their requestors with the L<dmarc_send_reports> program.

For aggregate reports that you have been sent, the L<dmarc_receive> program will parse the email messages (from IMAP, Mbox, or files) and save the report results into the L<Report Store|Mail::DMARC::Report::Store>.

The report store can use the same database to store reports you have received as well as reports you will send. There are several ways to identify the difference, including:

=over 4

=item *

received reports will have a null value for report_policy_published.rua

=item *

outgoing reports will have null values for report.uuid and report_record.count

=back

=head1 CLASSES

L<Mail::DMARC> - the perl interface for DMARC

L<Mail::DMARC::Policy> - a DMARC policy

L<Mail::DMARC::PurePerl> - Pure Perl implementation of DMARC

L<Mail::DMARC::Result> - the results of applying policy

L<Mail::DMARC::Report> - Reporting: the R in DMARC

=over 2

L<Mail::DMARC::Report::Send> - send reports via SMTP & HTTP

L<Mail::DMARC::Report::Receive> - receive and store reports from email, HTTP

L<Mail::DMARC::Report::Store> - a persistent data store for aggregate reports

L<Mail::DMARC::Report::View> - CLI and CGI methods for viewing reports

=back

L<Mail::DMARC::libopendmarc|http://search.cpan.org/~shari/Mail-DMARC-opendmarc> - an XS implementation using libopendmarc

=head1 METHODS

=head2 new

Create a DMARC object.

    my $dmarc = Mail::DMARC::PurePerl->new;

Populate it.

    $dmarc->source_ip('192.0.1.1');
    $dmarc->envelope_to('recipient.example.com');
    $dmarc->envelope_from('sender.example.com');
    $dmarc->header_from('sender.example.com');
    $dmarc->dkim( $dkim_verifier );
    $dmarc->spf([
        {   domain => 'example.com',
            scope  => 'mfrom',
            result => 'pass',
        },
        {
            scope  => 'helo',
            domain => 'mta.example.com',
            result => 'fail',
        },
    ]);

Run the request:

    my $result = $dmarc->validate();

Alternatively, pass in all the required parameters in one shot:

    my $dmarc = Mail::DMARC::PurePerl->new(
            source_ip     => '192.0.1.1',
            envelope_to   => 'example.com',
            envelope_from => 'cars4you.info',
            header_from   => 'yahoo.com',
            dkim          => $dkim_results,  # same format
            spf           => $spf_results,   # as previous example
            );
    my $result = $dmarc->validate();

=head2 source_ip

The remote IP that attempted sending the message. DMARC only uses this data for reporting to domains that request DMARC reports.

=head2 envelope_to

The domain portion of the RFC5321.RcptTo, (aka, the envelope recipient), and the bold portion in the following example:

=over 8

RCPT TO:&lt;user@B<example.com>>

=back

=head2 envelope_from

The domain portion of the RFC5321.MailFrom, (aka, the envelope sender). That is the the bold portion in the following example:

=over 8

MAIL FROM:&lt;user@B<example.com>>

=back

=head2 header_from

The domain portion of the RFC5322.From, aka, the From message header.

=over 8

From: Ultimate Vacation &lt;sweepstakes@B<example.com>>

=back

You can instead pass in the entire From: header with header_from_raw.

=head2 header_from_raw

Retrieve the header_from domain by parsing it from a raw From field/header. The domain portion is extracted by L<get_dom_from_header|Mail::DMARC::PurePerl#get_dom_from_header>, which is fast, generally effective, but also rather crude. It has limits, so read the description.

=head2 dkim

If Mail::DKIM::Verifier was used to validate the message, just pass in the Mail::DKIM::Verifier object that processed the message:

    $dmarc->dkim( $dkim_verifier );

Otherwise, pass in an array reference. Each member of the DKIM array results represents a DKIM signature in the message and consists of the 4 keys shown in this example:

    $dmarc->dkim( [
            {
                domain      => 'example.com',
                selector    => 'apr2013',
                result      => 'fail',
                human_result=> 'fail (body has been altered)',
            },
            {
                # 2nd signature, if present
            },
        ] );

The dkim results can also be build iteratively by passing in key value pairs or hash references for each signature in the message:

    $dmarc->dkim( domain => 'sig1.com', result => 'fail' );
    $dmarc->dkim( domain => 'sig2.com', result => 'pass' );
    $dmarc->dkim( { domain => 'example.com', result => 'neutral' } );

Each hash or hashref is appended to the dkim array.

Finally, you can pass a coderef which won't be called until the dkim method is used to read the dkim results.  It must return an array reference as described above.

The dkim result is an array reference.

=head3 domain

The d= parameter in the DKIM signature

=head3 selector

The s= parameter in the DKIM signature

=head3 result

The validation results of this signature. One of: none, pass, fail, policy, neutral, temperror, or permerror

=head3 human result

Additional information about the DKIM result. This is comparable to Mail::DKIM::Verifier->result_detail.

=head2 spf

The spf method works exactly the same as dkim. It accepts named arguments, a hashref, an arrayref, or a coderef:

    $dmarc->spf(
        domain => 'example.com',
        scope  => 'mfrom',
        result => 'pass',
    );

The SPF domain and result are required for DMARC validation and the scope is used for reporting.

=head3 domain

The SPF checked domain

=head3 scope

The scope of the checked domain: mfrom, helo

=head3 result

The SPF result code: none, neutral, pass, fail, softfail, temperror, or permerror.

=head1 DESIGN & GOALS

=head2 Correct

The DMARC spec is lengthy and evolving, making correctness a moving target. In cases where correctness is ambiguous, options are generally provided.

=head2 Easy to use

Providing an implementation of DMARC that SMTP utilities can utilize will aid DMARC adoption.

The list of dependencies appears long because of reporting. If this module is used without reporting, the number of dependencies not included with perl is about 5. See the [Prereq] versus [Prereq / Recommends] sections in dist.ini.

=head2 Maintainable

Since DMARC is evolving, this implementation aims to be straight forward and easy to alter and extend. The programming style is primarily OO, which carries a small performance penalty but dividends in maintainability.

When multiple options are available, such as when sending reports via SMTP or HTTP, calls should be made to the parent Send class to broker the request. When storing reports, calls are made to the Store class which dispatches to the SQL class. The idea is that if someone desired a data store other than those provided by perl's DBI class, they could easily implement their own. If you do, please fork it on GitHub and share.

=head2 Fast

If you deploy this in an environment where performance is insufficient, please profile the app and submit a report and preferably, patches.

=head1 SEE ALSO

L<Mail::DMARC on GitHub|https://github.com/msimerson/mail-dmarc>

2015-03 L<RFC 7489|https://tools.ietf.org/html/rfc7489>

DMARC L<Best Current Practices|http://tools.ietf.org/html/draft-crocker-dmarc-bcp-03>

=head1 HISTORY

The daddy of this perl module was a L<DMARC module for the qpsmtpd MTA|https://github.com/smtpd/qpsmtpd/blob/master/plugins/dmarc>.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=item *

Marc Bradshaw <marc@marcbradshaw.net>

=back

=head1 CONTRIBUTORS

=for stopwords Benny Pedersen Jean Paul Galea Marisa Clardy Priyadi Iman Nurcahyo Ricardo Signes

=over 4

=item *

Benny Pedersen <me@junc.eu>

=item *

Jean Paul Galea <jeanpaul@yubico.com>

=item *

Marisa Clardy <marisa@clardy.eu>

=item *

Priyadi Iman Nurcahyo <priyadi@priyadi.net>

=item *

Ricardo Signes <rjbs@cpan.org>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2024 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
