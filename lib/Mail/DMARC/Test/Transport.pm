package Mail::DMARC::Test::Transport;

# VERSION
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)
use Email::Sender::Transport::Test;

sub new($class) {
    my $self = {};
    return bless $self, $class;
}

{
    my $global_transport = Email::Sender::Transport::Test->new;

    sub get_test_transport {
        return $global_transport;
    }
}

sub get_transports_for( $self, $args = undef ) {
    my @transports;
    push @transports, $self->get_test_transport;
    return @transports;
}

1;
