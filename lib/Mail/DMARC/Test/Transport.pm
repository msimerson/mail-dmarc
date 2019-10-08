package Mail::DMARC::Test::Transport;
# VERSION
use strict;
use warnings;
use Email::Sender::Transport::Test;

sub new {
    my $class = shift;
    my $self = {};
    return bless $self, $class;
};

{
  my $global_transport = Email::Sender::Transport::Test->new;
  sub get_test_transport {
    return $global_transport;
  }
}

sub get_transports_for {
  my ( $self,$args ) = @_;
  my @transports;
  push @transports, $self->get_test_transport;
  return @transports;
}

1;
