package Mail::DMARC::Report::Aggregate;
# VERSION
use strict;
use warnings;

use Carp;
use Data::Dumper;
use XML::LibXML;

use parent 'Mail::DMARC::Base';
use Mail::DMARC::Report::Aggregate::Metadata;

sub metadata {
    my $self = shift;
    return $self->{metadata} if ref $self->{metadata};
    return $self->{metadata} = Mail::DMARC::Report::Aggregate::Metadata->new;
}

sub policy_published {
    my ( $self, $policy ) = @_;
    return $self->{policy_published} if ! $policy;
    croak "not a policy object!" if 'Mail::DMARC::Policy' ne ref $policy;
    return $self->{policy_published} = $policy;
}

sub record {   ## no critic (Ambiguous)
    my ($self, $record, @extra) = @_;
    if ( !$record) {
       return $self->{record} || [];
    }

    if (@extra) { croak "invalid args"; }

    if ('Mail::DMARC::Report::Aggregate::Record' ne ref $record) {
        croak "not a record object";
    }

    $self->{record} ||= [];

    push @{ $self->{record} }, $record;

    return $self->{record};
};

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
\t<version>1.0</version>
$meta
$pubp
$reco</feedback>
EO_XML
;
}

sub get_record_as_xml {
    my $self = shift;

    my $rec_xml;
    foreach my $rec ( @{ $self->{record} } ) {
        $rec_xml .= "\t<record>\n";
        my $ip = $rec->{row}{source_ip} or croak "no source IP!?";
        my $count = $rec->{row}{count} or croak "no count!?";
        $rec->{row}{policy_evaluated}{disposition} or croak "no disposition?";
        $ip    = XML::LibXML::Text->new( $ip )->toString();
        $count = XML::LibXML::Text->new( $count )->toString();
        $rec_xml
            .="\t\t<row>\n"
            . "\t\t\t<source_ip>$ip</source_ip>\n"
            . "\t\t\t<count>$count</count>\n"
            . $self->get_policy_evaluated_as_xml( $rec )
            . "\t\t</row>\n"
            . $self->get_identifiers_as_xml($rec)
            . $self->get_auth_results_as_xml($rec);
        $rec_xml .= "\t</record>\n";
    }
    return $rec_xml;
}

sub get_identifiers_as_xml {
    my ( $self, $rec ) = @_;
    my $id = "\t\t<identifiers>\n";
    foreach my $f (qw/ envelope_to envelope_from header_from /) {
        if ( $f eq 'header_from' ) {        # min occurs = 1
            croak "missing header_from!" if ! $rec->{identifiers}{$f};
        }
        elsif ( $f eq 'envelope_from') {    # min occurs = 1
            $rec->{identifiers}{$f} = '' if ! $rec->{identifiers}{$f};
        }
        elsif ( $f eq 'envelope_to' ) {     # min occurs = 0
            next if ! $rec->{identifiers}{$f};
        };

        my $val = XML::LibXML::Text->new( $rec->{identifiers}{$f} )->toString();
        $id .= "\t\t\t<$f>$val</$f>\n";
    }
    $id .= "\t\t</identifiers>\n";
    return $id;
}

sub get_auth_results_as_xml {
    my ( $self, $rec ) = @_;
    my $ar = "\t\t<auth_results>\n";

    foreach my $dkim_sig ( @{ $rec->{auth_results}{dkim} } ) {
        $ar .= "\t\t\t<dkim>\n";
        foreach my $g (qw/ domain selector result human_result /) {
            next if !defined $dkim_sig->{$g};
            my $val = XML::LibXML::Text->new( $dkim_sig->{$g} )->toString();
            $ar .= "\t\t\t\t<$g>$val</$g>\n";
        }
        $ar .= "\t\t\t</dkim>\n";
    }

    foreach my $spf ( @{ $rec->{auth_results}{spf} } ) {
        $ar .= "\t\t\t<spf>\n";
        foreach my $g (qw/ domain scope result /) {
            next if !defined $spf->{$g};
            my $val = XML::LibXML::Text->new( $spf->{$g} )->toString();
            $ar .= "\t\t\t\t<$g>$val</$g>\n";
        }
        $ar .= "\t\t\t</spf>\n";
    }

    $ar .= "\t\t</auth_results>\n";
    return $ar;
}

sub get_policy_published_as_xml {
    my $self = shift;
    my $pp = $self->policy_published or return '';
    my $xml = "\t<policy_published>\n\t\t<domain>$pp->{domain}</domain>\n";
    foreach my $f (qw/ adkim aspf p sp pct fo /) {
        my $v = $pp->{$f};
        # Set some default values for missing optional fields if necessary
        if ( $f eq 'sp' && !defined $v ) {
            $v = $pp->{'p'};
        }
        if ( $f eq 'pct' && !defined $v ) {
            $v = '100';
        }
        if ( $f eq 'fo' && !defined $v ) {
            $v = '0';
        }
        next if !defined $v;
        $v = XML::LibXML::Text->new( $v )->toString();
        $xml .= "\t\t<$f>$v</$f>\n";
    }
    $xml .= "\t</policy_published>";
    return $xml;
}

sub get_policy_evaluated_as_xml {
    my ( $self, $rec ) = @_;
    my $pe = "\t\t\t<policy_evaluated>\n";

    foreach my $f (qw/ disposition dkim spf /) {
        my $val = XML::LibXML::Text->new( $rec->{row}{policy_evaluated}{$f} )->toString();
        $pe .= "\t\t\t\t<$f>$val</$f>\n";
    }

    my $reasons = $rec->{row}{policy_evaluated}{reason};
    if ( $reasons && scalar @$reasons ) {
        foreach my $reason ( @$reasons ) {
            my $typeval    = XML::LibXML::Text->new( $reason->{type} )->toString();
            my $commentval = XML::LibXML::Text->new( $reason->{comment} )->toString();
            $pe .= "\t\t\t\t<reason>\n";
            $pe .= "\t\t\t\t\t<type>$typeval</type>\n";
            $pe .= "\t\t\t\t\t<comment>$commentval</comment>\n";
            $pe .= "\t\t\t\t</reason>\n";
        }
    };
    $pe .= "\t\t\t</policy_evaluated>\n";
    return $pe;
}

1;
# ABSTRACT: aggregate report object
__END__
sub {}

=head1 DESCRIPTION

This class is used as the canonization of an aggregate report.

When reports are received, the XML is parsed into an L<Aggregate|Mail::DMARC::Report::Aggregate> object, which then gets passed to the Report::Store and saved. When sending DMARC reports, data is extracted from the L<Store|Mail::DMARC::Report::Store> as an Aggregate object, exported as XML, and sent.

=head1 2013 Draft Description

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

This is a translation of the XML report format in the 2013 Draft, converted to perl data structures.

   feedback => {
      version          => 1.0,  # decimal
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
          fo     =>   string
      },
      record   => [
         {  row => {
               source_ip     =>   # IPAddress
               count         =>   # integer
               policy_evaluated => {       # min=1
                  disposition =>           # none, quarantine, reject
                  dkim        =>           # pass, fail
                  spf         =>           # pass, fail
                  reason      => [         # min 0, max unbounded
                      {   type    =>    # forwarded sampled_out, trusted_forwarder, mailing_list, local_policy, other
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
               spf => [            # min 1, max unbounded
                  {  domain  =>    # min 1
                     scope   =>    # min 1, helo, mfrom
                     result  =>    # min 1, none neutral pass fail softfail temperror permerror
                  }
               ]                   # ( unknown -> temperror, error -> permerror )
               dkim   => [                # min 0, max unbounded
                  {  domain       =>  ,   # min 1, the d= parameter in the signature
                     selector     =>  ,   # min 0, string
                     result       =>  ,   # none pass fail policy neutral temperror permerror
                     human_result =>      # min 0, string
                  },
               ],
            },
        ]
     },
  };

=cut
