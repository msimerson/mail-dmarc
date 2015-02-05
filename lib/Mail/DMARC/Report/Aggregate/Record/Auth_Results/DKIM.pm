package Mail::DMARC::Report::Aggregate::Record::Auth_Results::DKIM;
# VERSION
use strict;

use Carp;

sub new {
    my ( $class, @args ) = @_;

    my $self = bless {}, $class;

    # a bare hash
    return $self->_from_hash(@args) if scalar @args > 1;

    my $dkim = shift @args;
    croak "invalid dkim argument" if ! ref $dkim;

    return $dkim if ref $dkim eq $class;  # been here before...

    if ( ref $dkim eq 'Mail::DKIM::Verifier' ) {
        return $self->_from_mail_dkim($dkim);
    };

    return $self->_from_hashref($dkim) if 'HASH' eq ref $dkim;

    croak "invalid dkim argument";
}

sub domain {
    return $_[0]->{domain} if 1 == scalar @_;
    return $_[0]->{domain} =  $_[1];
}

sub selector {
    return $_[0]->{selector} if 1 == scalar @_;
    return $_[0]->{selector} =  $_[1];
}

sub result {
    return $_[0]->{result} if 1 == scalar @_;
    croak "invalid DKIM result" if ! grep { $_ eq $_[1] }
        qw/ pass fail neutral none permerror policy temperror /;
    return $_[0]->{result} =  $_[1];
}

sub human_result {
    return $_[0]->{human_result} if 1 == scalar @_;
    return $_[0]->{human_result} =  $_[1];
}

sub _from_hash {
    my ($self, %args) = @_;

    foreach my $key ( keys %args ) {
        $self->$key( $args{$key} );
    }

    $self->is_valid;
    return $self;
}

sub _from_hashref {
    return $_[0]->_from_hash(%{ $_[1] });
}

sub is_valid {
    my $self = shift;

    foreach my $f (qw/ domain result /) {
        if ( !$self->{$f} ) {
            croak "DKIM value $f is required!";
        }
    }
}

sub _from_mail_dkim {
    my ( $self, $dkim ) = @_;

    # A DKIM verifier will have result and signature methods.
    foreach my $s ( $dkim->signatures ) {
        next if ref $s eq 'Mail::DKIM::DkSignature';

        my $result = $s->result;

        if ($result eq 'invalid') {  # See GH Issue #21
            $result = 'temperror';
        }

        $self->domain( $s->domain );
        $self->selector( $s->selector );
        $self->result( $result );
        $self->human_result( $s->result_detail );
    }
    $self->is_valid;
    return $self;
}

1;

# ABSTRACT: auth_results/dkim section of a DMARC aggregate record
__END__
