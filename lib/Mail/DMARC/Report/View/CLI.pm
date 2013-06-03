package Mail::DMARC::Report::View::CLI;
# VERSION
use strict;
use warnings;

use Carp;
use Data::Dumper;

require Mail::DMARC::Report::Store;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub list {
    my $self    = shift;
    my $reports = $self->store->retrieve;
    foreach my $report ( reverse @$reports) {
        printf "%3s  %20s  %15s\n", @$report{qw/ rid from_domain begin /};
    }
    return $reports;
}

sub detail {
    my $self = shift;
    my $id = shift or croak "need an ID!";
    return $id;
}

sub store {
    my $self = shift;
    return $self->{store} if ref $self->{store};
    return $self->{store} = Mail::DMARC::Report::Store->new();
}

1;

# ABSTRACT: view locally stored DMARC reports
__END__

