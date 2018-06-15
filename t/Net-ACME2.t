#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;

use Digest::MD5;
use HTTP::Status;
use URI;
use JSON;

#----------------------------------------------------------------------

my $_ACME_KEY  = <<END;
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCkOYWppsEFfKHqIntkpUjmuwnBH3sRYP00YRdIhrz6ypRpxX6H
c2Q0IrSprutu9/dUy0j9a96q3kRa9Qxsa7paQj7xtlTWx9qMHvhlrG3eLMIjXT0J
4+MSCw5LwViZenh0obBWcBbnNYNLaZ9o31DopeKcYOZBMogF6YqHdpIsFQIDAQAB
AoGAN7RjSFaN5qSN73Ne05bVEZ6kAmQBRLXXbWr5kNpTQ+ZvTSl2b8+OT7jt+xig
N3XY6WRDD+MFFoRqP0gbvLMV9HiZ4tJ/gTGOHesgyeemY/CBLRjP0mvHOpgADQuA
+VBZmWpiMRN8tu6xHzKwAxIAfXewpn764v6aXShqbQEGSEkCQQDSh9lbnpB/R9+N
psqL2+gyn/7bL1+A4MJwiPqjdK3J/Fhk1Yo/UC1266MzpKoK9r7MrnGc0XjvRpMp
JX8f4MTbAkEAx7FvmEuvsD9li7ylgnPW/SNAswI6P7SBOShHYR7NzT2+FVYd6VtM
vb1WrhO85QhKgXNjOLLxYW9Uo8s1fNGtzwJAbwK9BQeGT+cZJPsm4DpzpIYi/3Zq
WG2reWVxK9Fxdgk+nuTOgfYIEyXLJ4cTNrbHAuyU8ciuiRTgshiYgLmncwJAETZx
KQ51EVsVlKrpFUqI4H72Z7esb6tObC/Vn0B5etR0mwA2SdQN1FkKrKyU3qUNTwU0
K0H5Xm2rPQcaEC0+rwJAEuvRdNQuB9+vzOW4zVig6HS38bHyJ+qLkQCDWbbwrNlj
vcVkUrsg027gA5jRttaXMk8x9shFuHB9V5/pkBFwag==
-----END RSA PRIVATE KEY-----
END

my $_TOS_URL = 'http://the-terms-of-service/are/here';

my $base_request_cr;

local *Net::ACME2::HTTP_Tiny::_base_request;
{
    no warnings 'redefine';
    *Net::ACME2::HTTP_Tiny::_base_request = sub { $base_request_cr->(@_) };
}

{
    package MyCA;

    use parent qw( Net::ACME2 );

    use constant {
        HOST => 'acme.someca.net',
        DIRECTORY_PATH => '/acme-directory',
    };
}

#{
#    package Mock_ACME_Response;
#
#    sub new { bless {} }
#
#    sub set_payload {
#        my ($self, $payload) = @_;
#
#        $self->{'_payload'} = $payload;
#
#        return $self;
#    }
#}

#----------------------------------------------------------------------
# new()

my $acme = MyCA->new( key => $_ACME_KEY );
isa_ok( $acme, 'MyCA', 'new() response' );

#----------------------------------------------------------------------

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Crypt;

my $nonce_counter = 0;
my %nonces;

my %registered_keys;

use constant _CONTENT_TYPE_JSON => ( 'content-type' => 'application/json' );

sub _verify_nonce {
    my ($args_hr) = @_;

    my $content_hr = JSON::decode_json($args_hr->{'content'});
    my $headers_hr = JSON::decode_json( MIME::Base64::decode_base64url( $content_hr->{'protected'} ) );

    my $nonce = $headers_hr->{'nonce'};

    if (!$nonce) {
        die "No nonce given!";
    }

    delete $nonces{$nonce} or do {
        die "Unrecognized nonce! ($nonce)";
    };

    return;
}

sub _new_nonce_header {
    my $new_nonce = "nonce-$nonce_counter";
    $nonces{$new_nonce} = 1;

    $nonce_counter++;

    return 'replay-nonce' => $new_nonce;
}

sub _verify_content_type {
    my ($args_hr) = @_;

    my $ctype = $args_hr->{'headers'}{'content-type'};
    if ($ctype ne 'application/jose+json') {
        die "Wrong content-type ($ctype)";
    }

    return;
}

$base_request_cr = sub {
    my ($self, $method, $url, $args_hr) = @_;

    my $host = MyCA::HOST();
    my $base_path = MyCA::DIRECTORY_PATH();

    my $uri = URI->new($url);
    die "Must be https! ($url)" if $uri->scheme() ne 'https';
    die "Wrong host! ($url)" if $uri->host() ne $host;

    my $path = $uri->path();

    my %dispatch = (
        "GET:$base_path" => sub {
            return {
                status => 'HTTP_OK',
                headers => {
                    _CONTENT_TYPE_JSON(),
                },
                content => {
                    meta => {
                        termsOfService => $_TOS_URL,
                    },

                    newNonce => "https://$host/my-new-nonce",
                    newAccount => "https://$host/my-new-account",
                },
            };
        },

        "HEAD:/my-new-nonce" => sub {
            return {
                status => 'HTTP_NO_CONTENT',
                headers => {
                    _new_nonce_header(),
                },
            };
        },

        'POST:/my-new-account' => sub {
            my $args_hr = shift;

            _verify_content_type($args_hr);
            _verify_nonce($args_hr);

            my ($key_obj, $header, $payload) = Test::Crypt::decode_acme2_jwt_extract_key($args_hr->{'content'});

            my $status;
            if ($registered_keys{ $key_obj->to_pem() }) {
                $status = 'OK';
            }
            else {
                $registered_keys{ $key_obj->to_pem() } = 1;
                $status = 'CREATED';
            }

            my %response;

            for my $name ( Net::ACME2::newAccount_booleans() ) {
                next if !exists $payload->{$name};

                if (ref($payload->{$name}) ne ref( JSON::true )) {
                    die "$name should be boolean, not “$name”";
                }

                $response{$name} = $payload->{$name};
            }

            return {
                status => "HTTP_$status",
                headers => {
                    _new_nonce_header(),
                    _CONTENT_TYPE_JSON(),
                    location => "https://$host/key/" . Digest::MD5::md5_hex($key_obj->to_pem()),
                },
                content => \%response,
            };
        },
    );

    my $dispatch_key = "$method:$path";

    my $todo_cr = $dispatch{$dispatch_key} or die "No action for “$dispatch_key”!";

    my $resp_hr = $todo_cr->($args_hr);

    $resp_hr->{'status'} = HTTP::Status->can( $resp_hr->{'status'} )->();
    $resp_hr->{'reason'} = HTTP::Status::status_message( $resp_hr->{'status'} );
    $resp_hr->{'success'} = HTTP::Status::is_success($resp_hr->{'status'});
    $resp_hr->{'uri'} = $url;

    ref && ($_ = JSON::encode_json($_)) for $resp_hr->{'content'};

    return $resp_hr;
};

#----------------------------------------------------------------------
# get_terms_of_service()

my $tos = $acme->get_terms_of_service();

is( $tos, $_TOS_URL, 'get_terms_of_service' );

#----------------------------------------------------------------------

my $created = $acme->create_new_account(
    termsOfServiceAgreed => 1,
);

is( $created, 1, 'create_new_account() on new account creation' );

$created = $acme->create_new_account();
is( $created, 0, 'create_new_account() if account already exists' );

done_testing();
