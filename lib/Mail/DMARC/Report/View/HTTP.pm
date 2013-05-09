package Mail::DMARC::Report::View::HTTP;
use strict;
use warnings;

use parent 'Mail::DMARC::Report';

sub new {
    my $class = shift;
    return bless {}, $class;
};

1;
# ABSTRACT: view locally stored DMARC reports
__END__

=head1 SYNOPSIS

A HTTP interface for the local DMARC report store.

=head1 DESCRIPTION

This is likely to be implemented almost entirely in JavaScript, loading jQuery, jQueriUI, the DataTables plugin, and retrieving the requisite files via CDNs.

=cut
