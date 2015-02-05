package Mail::DMARC::Report::Aggregate::Record::Auth_Results::SPF;
# VERSION
use strict;

use Carp;
use parent 'Mail::DMARC::Base';

sub new {
    my ( $class, @args ) = @_;

    my $self = bless {}, $class;

    if (0 == scalar @args) {
        $self->is_valid if $self->_unwrap( \$self->{callback} );
        return $self;
    }

    # a bare hash
    return $self->_from_hash(@args) if scalar @args > 1;

    my $spf = shift @args;
    return $spf if ref $spf eq $class;

    return $self->_from_hashref($spf) if 'HASH' eq ref $spf;
    return $self->_from_callback($spf) if 'CODE' eq ref $spf;
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
        $self->$key( $args{$key} );
    }

    $self->is_valid;
    return $self;
}

sub _from_hashref {
    return $_[0]->_from_hash(%{ $_[1] });
}

sub _from_callback {
    $_[0]->{callback} = $_[1];
}

sub _unwrap {
    my ( $self, $ref ) = @_;
    if (ref $$ref and ref $$ref eq 'CODE') {
        $$ref = $$ref->();
        return 1;
    }
    return;
}

sub is_valid {
    my $self = shift;

    foreach my $f (qw/ domain result scope /) {
        next if $self->{$f};
        croak "SPF $f is required!";
    }

    if ( $self->{result} =~ /^pass$/i && !$self->{domain} ) {
        croak "SPF pass MUST include the RFC5321.MailFrom domain!";
    }

    return 1;
}

1;

# ABSTRACT: auth_results/spf section of a DMARC aggregate record
__END__