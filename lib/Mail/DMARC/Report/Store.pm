package Mail::DMARC::Report::Store;
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC::Base';

sub store {
    my $self = shift;
    return $self->backend->store(@_);
};

sub retrieve {
    my $self = shift;
    return $self->backend->retrieve(@_);
};

sub backend {
    my $self = shift;
    my $backend = $self->config->{report_store}{backend};

    croak "no backend defined?!" if ! $backend;

    return $self->{$backend} if ref $self->{$backend};
    my $module = "Mail::DMARC::Report::Store::$backend";
    eval "use $module";
    if ( $@ ) {
        croak "Unable to load backend $backend: $@\n";
    };

    return $self->{$backend} = $module->new;
};

1;
# ABSTRACT: persistent storage broker for DMARC reports
__END__

=head1 DESCRIPTION

I struggled with choosing between a perl AnyDBM storage backend versus a SQL backend. I deployed with SQL because with a single SQL implementation, the user can choose from the wide availability of DBD drivers, including SQLite, MySQL, DBD (same as AnyDBM) and many others.

Others might like an alternative. This layer of indirection allows someone to write a new Mail::DMARC::Report::Store::MyGreatDB module, update their config file, and not alter the innards of Mail::DMARC.

=cut
