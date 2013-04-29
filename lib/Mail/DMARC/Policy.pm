package Mail::DMARC::Policy;
use strict;
use warnings;

sub new {
    my $class = shift;
    my $self = {
        p     => 'none',
        adkim => 'r',
        aspf  => 'r',
        pct   => 100,
    };
    my $pack = ref $class ? ref $class : $class;
    bless $self, $pack;
    if ( 1 == @_ ) {   # a string to parse
        return $self->parse( shift );
    };
    die "invalid arguments" if @_ && @_ % 2 != 0;
    return bless { %$self, @_ }, $pack;  # @_ values will override defaults 
};

# v=DMARC1;    (version)
sub v {
    return $_[0]->{v} if 1 == scalar @_;
    $_[0]->{v} = $_[1];
};

# p=none;      (disposition policy : reject, quarantine, none (monitor))
sub p {
    return $_[0]->{p} if 1 == scalar @_;
    $_[0]->{p} = $_[1];
};

# sp=reject;   (subdomain policy: default, same as p)
sub sp {
    return $_[0]->{sp} if 1 == scalar @_;
    $_[0]->{sp} = $_[1];
};

# adkim=s;     (dkim alignment: s=strict, r=relaxed)
sub adkim {
    return $_[0]->{adkim} if 1 == scalar @_;
    $_[0]->{adkim} = $_[1];
};

# aspf=r;      (spf  alignment: s=strict, r=relaxed)
sub aspf {
    return $_[0]->{aspf} if 1 == scalar @_;
    $_[0]->{aspf} = $_[1];
};

# rua=mailto: dmarc-feedback@example.com; (aggregate reports)
sub rua {
    return $_[0]->{rua} if 1 == scalar @_;
    $_[0]->{rua} = $_[1];
};

# ruf=mailto: dmarc-feedback@example.com; (forensic reports)
sub ruf {
    return $_[0]->{ruf} if 1 == scalar @_;
    $_[0]->{ruf} = $_[1];
};

# rf=afrf;     (report format: afrf, iodef)
sub rf {
    return $_[0]->{rf} if 1 == scalar @_;
    $_[0]->{rf} = $_[1];
};

# ri=8400;     (report interval)
sub ri {
    return $_[0]->{ri} if 1 == scalar @_;
    $_[0]->{ri} = $_[1];
};

# pct=50;      (percent of messages to filter)
sub pct {
    return $_[0]->{pct} if 1 == scalar @_;
    $_[0]->{pct} = $_[1];
};

sub is_valid {
    my %valid = map { $_ => 1 } qw/ none reject quarantine /;
    return $valid{$_[1]} ? 1 : 0;
};

sub parse {
    my ($self, $str) = @_;
    $str =~ s/\s//g;                             # remove all whitespace
    my %dmarc = map { split /=/, $_ } split /;/, $str;
    return bless { %$self, %dmarc }, ref $self;  # inherited defaults + overrides
#return Mail::DMARC::Policy->new( %dmarc );
}

1;
