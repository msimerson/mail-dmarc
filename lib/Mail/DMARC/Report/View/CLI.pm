package Mail::DMARC::Report::View::CLI;
use strict;
use warnings;

use Data::Dumper;

require Mail::DMARC::Report::Store;

sub new {
    my $class = shift;
    return bless {}, $class;
};

sub list {
    my $self = shift;
    foreach my $report ( @{$self->store->retrieve} ) {
        printf "%3s  %30s  %15s %15s\n", @$report{ qw/ id domain begin end / };
    };
    return 1;
};

sub store {
    my $self = shift;
    return $self->{store} if ref $self->{store};
    return $self->{store} = Mail::DMARC::Report::Store->new();
};

1;
# ABSTRACT: view locally stored DMARC reports
__END__

