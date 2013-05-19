package Mail::DMARC::Report;
use strict;
use warnings;

use Carp;
use Data::Dumper;

use parent 'Mail::DMARC::Base';

require Mail::DMARC::Report::Send;
require Mail::DMARC::Report::Store;
require Mail::DMARC::Report::Receive;
require Mail::DMARC::Report::URI;
require Mail::DMARC::Report::View;

sub init {
    my $self = shift;
    delete $_->{_record};
    return;
};

sub meta {
    my $self = shift;
    return $self->{_report}{meta} if ref $self->{_report}{meta};
    return $self->{_report}{meta} = Mail::DMARC::Report::metadata->new();
};

sub policy_published {
    my ($self, $policy) = @_;
    croak "not a policy object!" if 'Mail::DMARC::Policy' ne ref $policy;
    return $self->{_report}{policy_published} = $policy;
};

sub add_record {
    my ($self, $rrecord) = @_;
    croak "invalid record format!" if 'HASH' ne ref $rrecord;
    return push @{ $self->{_report}{record}}, $rrecord;
};

sub dump_report {
    my $self = shift;
    carp Dumper($self->{_report});
    return;
};

sub dmarc {
    my $self = shift;
    return $self->{dmarc};
};

sub receive {
    my $self = shift;
    return $self->{receive} if ref $self->{receive};
    return $self->{receive} = Mail::DMARC::Report::Receive->new;
};

sub sendit {
    my $self = shift;
    return $self->{sendit} if ref $self->{sendit};
    return $self->{sendit} = Mail::DMARC::Report::Send->new();
};

sub store {
    my $self = shift;
    return $self->{store} if ref $self->{store};
    return $self->{store} = Mail::DMARC::Report::Store->new();
};

sub uri {
    my $self = shift;
    return $self->{uri} if ref $self->{uri};
    return $self->{uri} = Mail::DMARC::Report::URI->new();
};

sub view {
    my $self = shift;
    return $self->{view} if ref $self->{view};
    return $self->{view} = Mail::DMARC::Report::View->new;
};

sub save_receiver {
    my $self = shift;
    return $self->store->backend->save_receiver(@_);
};

sub save_author {
    my $self = shift;
    return $self->store->backend->save_author(
            $self->{_report}{meta},
            $self->{_report}{policy_published},
            $self->{_report}{record},
            );
};

sub assemble_xml {
    my $self = shift;
    $self->{report_ref} = shift or croak "mising report!";
    my $meta = $self->get_report_metadata_as_xml;
    my $pubp = $self->get_policy_published_as_xml;
    my $reco = $self->get_record_as_xml;

    return <<"EO_XML"
<?xml version="1.0"?>
<feedback>
$meta
$pubp
$reco
</feedback>
EO_XML
;
};

sub get_record_as_xml {
    my $self = shift;
    my $rr = ${$self->{report_ref}};

    return '' if 0 == @{$rr->{rows}};  # no rows
    my %ips;
    my %reasons;
    foreach my $row ( @{$rr->{rows}} ) {
        $ips{ $row->{source_ip} }++;
        if ( $row->{reason} ) {
            foreach my $reason ( @{ $row->{reason} } ) {
                my $type = $reason->{type} or next;
                $reasons{$row->{source_ip}}{$type} = ($reason->{comment} || '');
            };
        };
    };

    my $rec_xml = " <record>\n";
    foreach my $row ( @{$rr->{rows}} ) {
        my $ip = $row->{source_ip} or croak "no source IP!?";
        next if ! defined $ips{$ip};  # already reported
        my $count = delete $ips{$ip};
        $rec_xml .= "  <row>\n"
            . "   <source_ip>$ip</source_ip>\n"
            . "   <count>$count</count>\n"
            .  $self->get_policy_evaluated_as_xml( $row, $reasons{$ip} )
            . "  </row>\n"
            .  $self->get_identifiers_as_xml( $row )
            .  $self->get_auth_results_as_xml( $row )
    };
    $rec_xml   .= " </record>";
    return $rec_xml;
};

sub get_identifiers_as_xml {
    my ($self, $row) = @_;
    my $id = "  <identifiers>\n";
    foreach my $f ( qw/ envelope_to envelope_from header_from / ) {
        next if ! $row->{$f};
        $id .= "   <$f>$row->{$f}</$f>\n";
    };
    $id .= "  </identifiers>\n";
    return $id;
};

sub get_auth_results_as_xml {
    my ($self, $row) = @_;
    my $ar = "  <auth_results>\n";

    foreach my $dkim_sig ( @{ $row->{auth_results}{dkim} } ) {
        $ar .= "   <dkim>\n";
        foreach my $g ( qw/ domain selector result human_result / ) {
            next if ! defined $dkim_sig->{$g};
            $ar .= "    <$g>$dkim_sig->{$g}</$g>\n";
        };
        $ar .= "   </dkim>\n";
    };

    foreach my $spf ( @{ $row->{auth_results}{spf} } ) {
        $ar .= "   <spf>\n";
        foreach my $g ( qw/ domain scope result / ) {
            next if ! defined $spf->{$g};
            $ar .= "    <$g>$spf->{$g}</$g>\n";
        };
        $ar .= "   </spf>\n";
    };

    $ar .= "  </auth_results>\n";
    return $ar;
};

sub get_policy_published_as_xml {
    my $self = shift;
    my $rr = ${$self->{report_ref}};
    return '' if ! $rr->{policy_published};
    my $pp = " <policy_published>\n  <domain>$rr->{domain}</domain>\n";
    foreach my $f ( qw/ adkim aspf p sp pct / ) {
        next if ! defined $rr->{policy_published}{$f};
        $pp .= "  <$f>$rr->{policy_published}{$f}</$f>\n";
    };
    $pp .= " </policy_published>";
    return $pp;
};

sub get_policy_evaluated_as_xml {
    my ($self, $row, $reasons) = @_;
    my $pe = "   <policy_evaluated>\n";

    foreach my $f ( qw/ disposition dkim spf / ) {
        $pe   .= "    <$f>$row->{$f}</$f>\n";
    };

    foreach my $reason ( keys %$reasons ) {
        $pe .= "    <reason>\n     <type>$reason</type>\n";
        $pe .= "     <comment>$reasons->{$reason}</comment>\n" if $reasons->{$reason};
        $pe .= "    </reason>\n";
    };
    $pe .= "   </policy_evaluated>\n";
    return $pe;
};

sub get_report_metadata_as_xml {
    my $self = shift;
    my $rr = ${$self->{report_ref}};
    my $meta = " <report_metadata>\n  <report_id>$rr->{id}</report_id>\n";
    foreach my $f ( qw/ org_name email extra_contact_info / ) {
        next if ! $self->config->{organization}{$f};
        $meta .= "  <$f>".$self->config->{organization}{$f}."</$f>\n";
    };
    $meta .= "  <date_range>\n   <begin>$rr->{begin}</begin>\n"
          .  "   <end>$rr->{end}</end>\n  </date_range>\n";
    $meta .= "  <error>$rr->{error}</error>\n" if $rr->{error};
    $meta .= " </report_metadata>";
    return $meta;
};

1;
# ABSTRACT: A DMARC report object

package Mail::DMARC::Report::metadata;
use strict;
use warnings;

use parent 'Mail::DMARC::Base';

sub org_name {
    return $_[0]->{org_name} if 1 == scalar @_;
    return $_[0]->{org_name} = $_[1];
};
sub email {
    return $_[0]->{email} if 1 == scalar @_;
    return $_[0]->{email} = $_[1];
};
sub extra_contact_info {
    return $_[0]->{extra_contact_info} if 1 == scalar @_;
    return $_[0]->{extra_contact_info} = $_[1];
};
sub report_id {
    return $_[0]->{report_id} if 1 == scalar @_;
    return $_[0]->{report_id} = $_[1];
};
sub date_range {
    return $_[0]->{date_range} if 1 == scalar @_;
#   croak "invalid date_range" if ('HASH' ne ref $_->[1]);
    return $_[0]->{date_range} = $_[1];
};
sub begin {
    return $_[0]->{date_range}{begin} if 1 == scalar @_;
    return $_[0]->{date_range}{begin} = $_[1];
};
sub end {
    return $_[0]->{date_range}{end} if 1 == scalar @_;
    return $_[0]->{date_range}{end} = $_[1];
};
sub error {
    return $_[0]->{error} if 1 == scalar @_;
    return push @{ $_[0]->{error}}, $_[1];
};
sub domain {
    return $_[0]->{domain} if 1 == scalar @_;
    return $_[0]->{domain} = $_[1];
};
sub uuid {
    return $_[0]->{uuid} if 1 == scalar @_;
    return $_[0]->{uuid} = $_[1];
};

1;

__END__
sub {}

=head1 DESCRIPTION

DMARC reports are information that a DMARC implementing Mail Transfer Agent (MTA) sends to Author Domains and also something that an Author Domain owner receives from other DMARC implementing MTAs. Mail::DMARC supports both roles, as a sender and a receiver.

=head2 Report Sender

See L<Mail::DMARC::Report::Send>

    1. store reports
    2. bundle aggregated reports
    3. format report in XML
    4. gzip the XML
    5. deliver report to Author Domain

=head2 Report Receiver

See L<Mail::DMARC::Report::Receive>

    1. accept reports via HTTP or SMTP
    2. parse the compressed XML message
    3. store the report
    4. present stored data

=head1 AGGREGATE REPORTS

The report SHOULD include the following data:

   o  Enough information for the report consumer to re-calculate DMARC
      disposition based on the published policy, message dispositon, and
      SPF, DKIM, and identifier alignment results. {R12}

   o  Data for each sender subdomain separately from mail from the
      sender's organizational domain, even if no subdomain policy is
      applied. {R13}

   o  Sending and receiving domains {R17}

   o  The policy requested by the Domain Owner and the policy actually
      applied (if different) {R18}

   o  The number of successful authentications {R19}

   o  The counts of messages based on all messages received even if
      their delivery is ultimately blocked by other filtering agents {R20}

Aggregate reports are most useful when they all cover a common time
period.  By contrast, correlation of these reports from multiple
generators when they cover incongruous time periods is difficult or
impossible.  Report generators SHOULD, wherever possible, adhere to
hour boundaries for the reporting period they are using.  For
example, starting a per-day report at 00:00; starting per-hour
reports at 00:00, 01:00, 02:00; et cetera.  Report Generators using a
24-hour report period are strongly encouraged to begin that period at
00:00 UTC, regardless of local timezone or time of report production,
in order to facilitate correlation.

=head2 Verify External Destinations

  1.  Extract the host portion of the authority component of the URI.
       Call this the "destination host".

   2.  Prepend the string "_report._dmarc".

   3.  Prepend the domain name from which the policy was retrieved.

   4.  Query the DNS for a TXT record at the constructed name.  If the
       result of this request is a temporary DNS error of some kind
       (e.g., a timeout), the Mail Receiver MAY elect to temporarily
       fail the delivery so the verification test can be repeated later.

   5.  If the result includes no TXT resource records or multiple TXT
       resource records, a positive determination of the external
       reporting relationship cannot be made; stop.

   6.  Parse the result, if any, as a series of "tag=value" pairs, i.e.,
       the same overall format as the policy record.  In particular, the
       "v=DMARC1" tag is mandatory and MUST appear first in the list.
       If at least that tag is present and the record overall is
       syntactically valid per Section 6.3, then the external reporting
       arrangement was authorized by the destination ADMD.

   7.  If a "rua" or "ruf" tag is thus discovered, replace the
       corresponding value extracted from the domain's DMARC policy
       record with the one found in this record.  This permits the
       report receiver to override the report destination.  However, to
       prevent loops or indirect abuse, the overriding URI MUST use the
       same destination host from the first step.

=head1 ERROR REPORTS

12.2.4.  Error Reports

When a Mail Receiver is unable to complete delivery of a report via
any of the URIs listed by the Domain Owner, the Mail Receiver SHOULD
generate an error message.  An attempt MUST be made to send this
report to all listed "mailto" URIs and MAY also be sent to any or all
other listed URIs.

The error report MUST be formatted per [MIME].  A text/plain part
MUST be included that contains field-value pairs such as those found
in Section 2 of [DSN].  The fields required, which may appear in any
order, are:

Report-Date:  A [MAIL]-formatted date expression indicating when the transport failure occurred.

Report-Domain:  The domain-name about which the failed report was generated.

Report-ID:  The Report-ID: that the report tried to use.

Report-Size:  The size, in bytes, of the report that was unable to be
    sent.  This MUST represent the number of bytes that the Mail
    Receiver attempted to send.  Where more than one transport system
    was attempted, the sizes may be different; in such cases, separate
    error reports MUST be generated so that this value matches the
    actual attempt that was made.  For example, a "mailto" error
    report would be sent to the "mailto" URIs with one size, while the
    "https" reports might be POSTed to those URIs with a different
    size, as they have different transport and encoding requirements.

Submitter:  The domain-name representing the Mail Receiver that generated, but was unable to submit, the report.

Submitting-URI:  The URI(s) to which the Mail Receiver tried, but failed, to submit the report.

An additional text/plain part MAY be included that gives a human-
readable explanation of the above, and MAY also include a URI that
can be used to seek assistance.

[NOTE: A more rigorous syntax specification, including ABNF and
possible registration of a new media type, will be added here when
more operational experience is acquired.]


=head1 AFRF reports



=head1 IODEF reports

https://datatracker.ietf.org/doc/draft-kucherawy-dmarc-base/?include_text=1

Section 3.5 Out of Scope:

    This first version of DMARC supports only a single reporting format.

=cut
