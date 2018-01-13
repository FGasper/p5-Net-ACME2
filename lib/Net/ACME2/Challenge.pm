package Net::ACME2::Challenge;

=encoding utf-8

=head1 NAME

Net::ACME2::Order

=head1 DESCRIPTION

The ACME Challenge object.

(NB: The specification doesn’t seem to define this as a resource
per se.)

Note that C<http-01> challenges use L<Net::ACME2::Challenge::http_01>.

=cut

use strict;
use warnings;

use parent qw( Net::ACME2::AccessorBase );

use Net::ACME2::X ();

use constant _ACCESSORS => (
    'url',
    'type',
    'token',
    'status',
    'validated',
    #'keyAuthorization',
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

=cut

#my $ERROR_CLASS;
#
#BEGIN {
#    $ERROR_CLASS = 'Net::ACME2::Error';
#}
#
#sub new {
#    my ( $class, %opts ) = @_;
#
#    if ( $opts{'error'} && !Net::ACME2::Utils::thing_isa($opts{'error'}, $ERROR_CLASS) ) {
#        die Net::ACME2::X->create( 'InvalidParameter', "“error” must be an instance of “$ERROR_CLASS”, not “$opts{'error'}”!" );
#    }
#
#    return $class->SUPER::new( %opts );
#}

#sub set_status {
#    my ($self, $value) = @_;
#
#    $self->{'_status'} = $value;
#
#    return $self;
#}
#
#sub set_validated {
#    my ($self, $value) = @_;
#
#    $self->{'_validated'} = $value;
#
#    return $self;
#}

1;
