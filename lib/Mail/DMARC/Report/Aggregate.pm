package Mail::DMARC::Report::Aggregate;
use strict;
use warnings;

use Carp;
use Data::Dumper;

use parent 'Mail::DMARC::Base';

sub metadata {
    my $self = shift;
    return $self->{metadata} if ref $self->{metadata};
    return $self->{metadata} = Mail::DMARC::Report::Aggregate::Metadata->new();
}

sub policy_published {
    my ( $self, $policy ) = @_;
    return $self->{policy_published} if ! $policy;
    croak "not a policy object!" if 'Mail::DMARC::Policy' ne ref $policy;
    return $self->{policy_published} = $policy;
}

sub record {   ## no critic (Ambiguous)
    my ( $self, $rrecord ) = @_;
    return $self->{record} if ! defined $rrecord;
    croak "invalid record format!" if 'HASH' ne ref $rrecord;
    return push @{ $self->{record} }, $rrecord;
}

sub dump_report {
    my $self = shift;
    carp Dumper( $self->{metadata}, $self->{policy_published}, $self->{record} );
    return;
}

sub as_xml {
    my $self = shift;
    my $meta = $self->metadata->as_xml;
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
}

sub get_record_as_xml {
    my $self = shift;

    return '' if ! $self->{record} || 0 == @{ $self->{record} };  # no rows

    my (%ips, %reasons);  # aggregate the connections per IP
    foreach my $row ( @{ $self->{record} } ) {
        $ips{ $row->{source_ip} }++;
        if ( $row->{reason} ) {
            foreach my $reason ( @{ $row->{reason} } ) {
                my $type = $reason->{type} or next;
                $reasons{ $row->{source_ip} }{$type}
                    = ( $reason->{comment} || '' );
            }
        }
    }

    my $rec_xml = " <record>\n";
    foreach my $row ( @{ $self->{record} } ) {
        my $ip = $row->{source_ip} or croak "no source IP!?";
        $row->{policy_evaluated}{disposition} or croak "no disposition?";
        next if !defined $ips{$ip};    # already reported
        my $count = delete $ips{$ip};
        $rec_xml
            .= "  <row>\n"
            . "   <source_ip>$ip</source_ip>\n"
            . "   <count>$count</count>\n"
            . $self->get_policy_evaluated_as_xml( $row, $reasons{$ip} )
            . "  </row>\n"
            . $self->get_identifiers_as_xml($row)
            . $self->get_auth_results_as_xml($row);
    }
    $rec_xml .= " </record>";
    return $rec_xml;
}

sub get_identifiers_as_xml {
    my ( $self, $row ) = @_;
    my $id = "  <identifiers>\n";
    foreach my $f (qw/ envelope_to envelope_from header_from /) {
        next if !$row->{$f};
        $id .= "   <$f>$row->{$f}</$f>\n";
    }
    $id .= "  </identifiers>\n";
    return $id;
}

sub get_auth_results_as_xml {
    my ( $self, $row ) = @_;
    my $ar = "  <auth_results>\n";

    foreach my $dkim_sig ( @{ $row->{auth_results}{dkim} } ) {
        $ar .= "   <dkim>\n";
        foreach my $g (qw/ domain selector result human_result /) {
            next if !defined $dkim_sig->{$g};
            $ar .= "    <$g>$dkim_sig->{$g}</$g>\n";
        }
        $ar .= "   </dkim>\n";
    }

    foreach my $spf ( @{ $row->{auth_results}{spf} } ) {
        $ar .= "   <spf>\n";
        foreach my $g (qw/ domain scope result /) {
            next if !defined $spf->{$g};
            $ar .= "    <$g>$spf->{$g}</$g>\n";
        }
        $ar .= "   </spf>\n";
    }

    $ar .= "  </auth_results>\n";
    return $ar;
}

sub get_policy_published_as_xml {
    my $self = shift;
    my $pp = $self->policy_published or return '';
    my $xml = " <policy_published>\n  <domain>$pp->{domain}</domain>\n";
    foreach my $f (qw/ adkim aspf p sp pct /) {
        next if !defined $pp->{$f};
        $xml .= "  <$f>$pp->{$f}</$f>\n";
    }
    $xml .= " </policy_published>";
    return $xml;
}

sub get_policy_evaluated_as_xml {
    my ( $self, $row, $reasons ) = @_;
    my $pe = "   <policy_evaluated>\n";

    foreach my $f (qw/ disposition dkim spf /) {
        $pe .= "    <$f>$row->{policy_evaluated}{$f}</$f>\n";
    }

    foreach my $reason ( keys %$reasons ) {
        next if ! $reason;
        $pe .= "    <reason>\n     <type>$reason</type>\n";
        $pe .= "     <comment>$reasons->{$reason}</comment>\n"
            if $reasons->{$reason};
        $pe .= "    </reason>\n";
    }
    $pe .= "   </policy_evaluated>\n";
    return $pe;
}

1;
# ABSTRACT: DMARC aggregate report

package Mail::DMARC::Report::Aggregate::Metadata;
use strict;
use warnings;

use parent 'Mail::DMARC::Base';

sub org_name {
    return $_[0]->{org_name} if 1 == scalar @_;
    return $_[0]->{org_name} = $_[1];
}

sub email {
    return $_[0]->{email} if 1 == scalar @_;
    return $_[0]->{email} = $_[1];
}

sub extra_contact_info {
    return $_[0]->{extra_contact_info} if 1 == scalar @_;
    return $_[0]->{extra_contact_info} = $_[1];
}

sub report_id {
    return $_[0]->{report_id} if 1 == scalar @_;
    return $_[0]->{report_id} = $_[1];
}

sub date_range {
    return $_[0]->{date_range} if 1 == scalar @_;

    #   croak "invalid date_range" if ('HASH' ne ref $_->[1]);
    return $_[0]->{date_range} = $_[1];
}

sub begin {
    return $_[0]->{date_range}{begin} if 1 == scalar @_;
    return $_[0]->{date_range}{begin} = $_[1];
}

sub end {
    return $_[0]->{date_range}{end} if 1 == scalar @_;
    return $_[0]->{date_range}{end} = $_[1];
}

sub error {
    return $_[0]->{error} if 1 == scalar @_;
    return push @{ $_[0]->{error} }, $_[1];
}

sub domain {
# this is where locally generated reports store the recipient domain
    return $_[0]->{domain} if 1 == scalar @_;
    return $_[0]->{domain} = $_[1];
}

sub uuid {
    return $_[0]->{uuid} if 1 == scalar @_;
    return $_[0]->{uuid} = $_[1];
}

sub as_xml {
    my $self = shift;
    my $meta = " <report_metadata>\n  <report_id>"
             . $self->report_id . "</report_id>\n";

    foreach my $f (qw/ org_name email extra_contact_info /) {
        my $val = $self->$f or next;
        $meta .= "  <$f>$val</$f>\n";
    }
    $meta .= "  <date_range>\n   <begin>" . $self->begin . "</begin>\n"
          .  "   <end>" . $self->end . "</end>\n  </date_range>\n";

    my $errors = $self->error;
    if ( $errors && @$errors ) {
        foreach my $err ( @$errors ) {
            $meta .= "  <error>$err</error>\n";
        };
    };
    $meta .= " </report_metadata>";
    return $meta;
}

1;

__END__
sub {}

=head1 DESCRIPTION

AGGREGATE REPORTS

The report SHOULD include the following data:

   o  Enough information for the report consumer to re-calculate DMARC
      disposition based on the published policy, message disposition, and
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


=head1 Report Structure

This is a translation of the XML report format in the 2013 Draft, converted to perl data structions.

   feedback => {
      version          => 1,  # decimal
      report_metadata  => {                # info about DMARC reporter
          report_id          => string
          org_name           => 'Art Farm',
          email              => 'no-reply@theartfarm.com',
          extra_contact_info => string     # min 0
          date_range         => {
              begin          => epoch time,
              end            => epoch time,
          },
          error              => string,   # min 0, max unbounded
      },
      policy_published => {
          domain =>   string
          adkim  =>   r, s
          aspf   =>   r, s
          p      =>   none, quarantine, reject
          sp     =>   none, quarantine, reject
          pct    =>   integer
      },
      record   => [
         {  row => {
               source_ip     =>   # IPAddress
               count         =>   # integer
               policy_evaluated => {       # min=0
                  disposition =>           # none, quarantine, reject
                  dkim        =>           # pass, fail
                  spf         =>           # pass, fail
                  reason      => [         # min 0, max unbounded
                      {   type    =>    # forwarded sampled_out ...
                          comment =>    # string, min 0
                      },
                  ],
                }
            },
            identifiers => {
                envelope_to    min=0
                envelope_from  min=1
                header_from    min=1
            },
            auth_results => {
               spf => [           # min 1, max unbounded
                  {  domain  =>    # min 1
                     scope   =>    # helo, mfrom  -  min 1
                     result  =>    # none neutral ...
                  }
               ]                   # ( unknown -> temperror, error -> permerror )
               dkim   => [                # min 0, max unbounded
                  {  domain       =>  ,   # the d= parameter in the signature
                     selector     =>  ,   # min 0
                     result       =>  ,   # none pass fail policy ...
                     human_result =>      # min 0
                  },
               ],
            },
        ]
     },
  };

=cut
