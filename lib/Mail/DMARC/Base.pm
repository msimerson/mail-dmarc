package Mail::DMARC::Base;
use strict;
use warnings;

use Carp;
use Config::Tiny;

sub new {
    my ($class, @args) = @_;
    croak "invalid args" if scalar @args % 2 != 0;
    return bless {
        config_file => 'mail-dmarc.ini',
        @args,    # this may override config_file
    }, $class;
};

sub config {
    my $self = shift;
    return $self->{config} if ref $self->{config};
    return $self->{config} = $self->get_config();
};  
    
sub get_config {
    my $self = shift;
    my $file = $self->{config_file} or croak;
    my @dirs = qw[ /usr/local/etc /opt/local/etc /etc ./ ];
    foreach my $d ( @dirs ) {
        next if ! -d $d;
        next if ! -e "$d/$file";
        croak "unreadable file: $d/$file" if ! -r "$d/$file";
        my $Config = Config::Tiny->new;
        return Config::Tiny->read( "$d/$file" );
    };
    croak "unable to find config file $file\n";
}

1;
# ABSTRACT: utility functions
__END__


