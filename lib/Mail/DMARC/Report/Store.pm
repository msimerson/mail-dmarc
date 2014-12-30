package Mail::DMARC::Report::Store;
our $VERSION = '1.20141230'; # VERSION
use strict;
use warnings;

use Carp;

use parent 'Mail::DMARC::Base';

sub delete_report {
    my $self = shift;
    return $self->backend->delete_report(@_);
}

sub error {
    my $self = shift;
    return $self->backend->insert_error(@_);
}

sub retrieve {
    my $self = shift;
    return $self->backend->retrieve(@_);
}

sub retrieve_todo {
    my $self = shift;
    return $self->backend->retrieve_todo(@_);
}

sub backend {
    my $self    = shift;
    my $backend = $self->config->{report_store}{backend};

    croak "no backend defined?!" if !$backend;

    return $self->{$backend} if ref $self->{$backend};
    my $module = "Mail::DMARC::Report::Store::$backend";
    eval "use $module";    ## no critic (Eval)
    if ($@) {
        croak "Unable to load backend $backend: $@\n";
    }

    return $self->{$backend} = $module->new;
}

1;

# ABSTRACT: persistent storage broker for reports

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Store - persistent storage broker for reports

=head1 VERSION

version 1.20141230

=head1 SYNOPSIS

=head1 DESCRIPTION

At present, the only storage module is L<SQL|Mail::DMARC::Report::Store::SQL>.

I experimented with perl's AnyDBM storage backend, but chose to deploy with SQL because a single SQL implementation supports many DBD drivers, including SQLite, MySQL, and DBD (same as AnyDBM).

This Store class provides a layer of indirection, allowing one to write a new Mail::DMARC::Report::Store::MyGreatDB module, update their config file, and not alter the innards of Mail::DMARC. Much.

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=item *

Davide Migliavacca <shari@cpan.org>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
