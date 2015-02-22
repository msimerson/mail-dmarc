package Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
# VERSION
use strict;

use Carp;
use parent 'Mail::DMARC::Base';

sub new {
    my ( $class, @args ) = @_;

    my $self = bless {}, $class;

    if (0 == scalar @args) {
        return $self;
    }

    # a bare hash
    return $self->_from_hash(@args) if scalar @args > 1;

    my $spf = shift @args;
    return $spf if ref $spf eq $class;

    return $self->_from_hashref($spf) if 'HASH' eq ref $spf;

    croak "invalid spf argument";
}

sub domain {
    return $_[0]->{domain} if 1 == scalar @_;
    return $_[0]->{domain} =  $_[1];
}

sub result {
    return $_[0]->{result} if 1 == scalar @_;
    croak if !$_[0]->is_valid_spf_result( $_[1] );
    return $_[0]->{result} =  $_[1];
}

sub scope {
    return $_[0]->{scope} if 1 == scalar @_;
    croak if ! $_[0]->is_valid_spf_scope( $_[1] );
    return $_[0]->{scope} =  $_[1];
}

sub _from_hash {
    my ($self, %args) = @_;

    foreach my $key ( keys %args ) {
        # scope is frequently absent on received reports
        next if ($key eq 'scope' && !$args{$key});
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

    foreach my $f (qw/ domain result scope /) {
        next if $self->{$f};
        warn "SPF $f is required but missing!\n";
        return 0;
    }

    if ( $self->{result} =~ /^pass$/i && !$self->{domain} ) {
        warn "SPF pass MUST include the RFC5321.MailFrom domain!\n";
        return 0;
    }

    return 1;
}

1;

# ABSTRACT: auth_results/spf section of a DMARC aggregate record
__END__
