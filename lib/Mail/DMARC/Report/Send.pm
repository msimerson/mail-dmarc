package Mail::DMARC::Report::Send;
use strict;
use warnings;

use Carp;
use Encode;
use IO::Compress::Gzip;
use IO::Compress::Zip;

use lib 'lib';
use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Send::SMTP;
use Mail::DMARC::Report::Send::HTTP;
use Mail::DMARC::Report::URI;

sub send_rua {
    my ($self, $report, $xml) = @_;

    my $shrunk = $self->compress_report($xml);
    my $bytes = length Encode::encode_utf8($shrunk);

    my $uri_ref = $self->uri->parse($$report->{policy_published}{rua});
    my $sent = 0;
    foreach my $u_ref ( @$uri_ref ) {
        my $method = $u_ref->{uri};
        my $max = $u_ref->{max_bytes};

        if ( $max && $bytes > $max ) {
            carp "skipping $method: report size ($bytes) larger than $max\n";
            next;
        };

        if ( 'mailto:' eq substr($method,0,7) ) {
            $self->send_via_smtp($method, $report, $shrunk) and $sent++;
        };
        if ( 'http:' eq substr($method,0,5) ) {
            $self->http->post($method,$report, $shrunk) and $sent++;
        };
    };
    return $sent;
};

sub human_summary {
    my ($self, $report) = @_;

    my $rows = scalar @{ $$report->{rows} };
    my $OrgName = $self->config->{organization}{org_name};
    my $pass = grep { $_->{dkim} eq 'pass' || $_->{spf} eq 'pass' } @{ $$report->{rows} };
    my $fail = grep { $_->{dkim} ne 'pass' && $_->{spf} ne 'pass' } @{ $$report->{rows} };
    my $ver = $Mail::DMARC::VERSION || ''; # undef in author environ
    my $from = $$report->{domain};

    return <<"EO_REPORT"

This is a DMARC aggregate report for $from

$rows rows.
$pass passed.
$fail failed.

Submitted by $OrgName
Generated with Mail::DMARC $ver

EO_REPORT
;
};

sub compress_report {
    my ($self, $xml) = @_;

    my $shrunk;
    my $zipper = { gz  => \&IO::Compress::Gzip::gzip,  # 2013 draft
                   zip => \&IO::Compress::Zip::zip,    # legacy format
                 };
    my $cf = (time > 1372662000) ? 'gz' : 'zip';       # gz after 7/1/13
    $zipper->{$cf}->( $xml, \$shrunk ) or croak "unable to compress: $!";
    return $shrunk;
};

sub send_via_smtp {
    my ($self,$method,$report,$shrunk) = @_;
    my $rid = $$report->{id};
    my $dom = $$report->{domain};
    my ($to) = (split /:/, $method)[-1];
    carp "sending mailto $to\n";
# TODO: check results, append error to report if failed
    return $self->smtp->email(
        to            => $to,
        subject       => $self->smtp->get_subject({report_id=>$rid,policy_domain=>$dom}),
        body          => $self->human_summary($report),
        report        => $shrunk,
        policy_domain => $dom,
        begin         => $$report->{begin},
        end           => $$report->{end},
        report_id     => $rid,
        );
};

sub http {
    my $self = shift;
    return $self->{http} if ref $self->{http};
    return $self->{http} = Mail::DMARC::Report::Send::HTTP->new();
};

sub smtp {
    my $self = shift;
    return $self->{smtp} if ref $self->{smtp};
    return $self->{smtp} = Mail::DMARC::Report::Send::SMTP->new();
};

sub uri {
    my $self = shift;
    return $self->{uri} if ref $self->{uri};
    return $self->{uri} = Mail::DMARC::Report::URI->new();
};

1;
# ABSTRACT: send a DMARC report object
__END__
sub {}

=head1 DESCRIPTION

Send DMARC reports, via SMTP or HTTP.

=head2 Report Sender

A report sender needs to:

  1. store reports
  2. bundle aggregated reports
  3. format report in XML
  4. gzip the XML
  5. deliver report to Author Domain

=head1 12.2.1 Email

L<Mail::DMARC::Report::Send::SMTP>

=head1 12.2.2. HTTP

L<Mail::DMARC::Report::Send::HTTP>

=head1 12.2.3. Other Methods

Other registered URI schemes may be explicitly supported in later versions.

=cut
