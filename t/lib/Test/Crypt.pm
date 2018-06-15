package Test::Crypt;

#----------------------------------------------------------------------
# To avoid needing Crypt::JWT for tests.
#----------------------------------------------------------------------

use strict;
use warnings;

BEGIN {
    if ( $^V ge v5.10.1 ) {
        require autodie;
    }
}

use Carp;

use Call::Context ();
use JSON ();
use MIME::Base64 ();

use Crypt::Perl::PK ();

#A stripped-down copy of Crypt::JWT::decode_jwt() that only knows
#how to do RSA SHA256, “full” form. (Copied & adapted from Net::ACME.)
sub decode_acme2_jwt {
    my ($token, $key_text) = @_;

    Call::Context::must_be_list();

    my $token_hr = JSON::decode_json($token);

    my $signed = "$token_hr->{'protected'}.$token_hr->{'payload'}";
    my $signature = MIME::Base64::decode_base64url($token_hr->{'signature'});

    verify_rs256( $key_text, $signed, $signature );

    my ($header, $payload) = @{$token_hr}{'protected', 'payload'};

    $_ = MIME::Base64::decode_base64url($_) for ($header, $payload);

    $payload = JSON::decode_json($payload) if $payload =~ m<\A[ \[ \{ ]>x;

    return JSON::decode_json($header), $payload;
}

sub decode_acme2_jwt_extract_key {
    my ($token) = @_;

    my $token_hr = JSON::decode_json($token);

    my $header_hr = JSON::decode_json( MIME::Base64::decode_base64url($token_hr->{'protected'}) );

    my $key_obj = Crypt::Perl::PK::parse_jwk( $header_hr->{'jwk'} );

    return ($key_obj, decode_acme2_jwt($token, $key_obj->to_pem()));
}

sub verify_rs256 {
    my ($key, $message, $signature) = @_;

    confess "No key!" if !$key;

    my $kobj = Crypt::Perl::PK::parse_key($key);

    die "JWT verification failed!" if !$kobj->verify_RS256($message, $signature);

    return;
}

1;
