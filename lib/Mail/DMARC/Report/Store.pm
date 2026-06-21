package Mail::DMARC::Report::Store;
our $VERSION = '2.20260621';
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';    ## no critic (ProhibitNoWarnings)
use feature 'try';
no warnings 'experimental::try';    ## no critic (ProhibitNoWarnings)

use Carp;
use Module::Load;

use parent 'Mail::DMARC::Base';

sub delete_report( $self, @args ) {
    return $self->backend->delete_report(@args);
}

sub error( $self, @args ) {
    return $self->backend->insert_error(@args);
}

sub retrieve( $self, @args ) {
    return $self->backend->retrieve(@args);
}

sub next_todo( $self, @args ) {
    return $self->backend->next_todo(@args);
}

sub retrieve_todo( $self, @args ) {
    return $self->backend->retrieve_todo(@args);
}

sub backend($self) {
    my $backend = $self->config->{report_store}{backend};

    croak "no backend defined?!" if !$backend;

    return $self->{$backend} if ref $self->{$backend};
    my $module = "Mail::DMARC::Report::Store::$backend";
    try {
        load $module;
    }
    catch ($error) {
        croak "Unable to load backend $backend: $error\n";
    }

    return $self->{$backend} = $module->new;
}

1;

__END__

=pod

=head1 NAME

Mail::DMARC::Report::Store - persistent storage broker for reports

=head1 VERSION

version 2.20260621

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

=item *

Marc Bradshaw <marc@marcbradshaw.net>

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2026 by Matt Simerson.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
