package Net::ACME2::Challenge;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Net::ACME2::Challenge

=head1 DESCRIPTION

The ACME Challenge object.

You probably won’t instantiate these directly; they’re created automatically
as part of L<Net::ACME2::Authorization> instantiation.

=cut

use parent qw( Net::ACME2::AccessorBase );

use Net::ACME2::Error ();

use constant _ACCESSORS => (
    'url',
    'type',
    'status',
    'validated',
    'token',
);

=head1 ACCESSORS

These provide text strings as defined in the ACME specification.

=over

=item * B<url()>

=item * B<type()>

=item * B<token()>

=item * B<status()>

=item * B<validated()>

=back

The C<error()> accessor provides the error object as a
L<Net::ACME2::Error> instance (or undef if there is no error).

=cut

sub error {
    my ($self) = @_;

    return $self->{'_error'} && Net::ACME2::Error->new( %{ $self->{'_error'} } );
}

1;
