package Net_ACME2_Example_Async;

use strict;
use warnings;

# Without __SUB__ we get memory leaks.
use feature 'current_sub';

use FindBin;
use lib "$FindBin::Bin/../lib";

use Crypt::Perl::ECDSA::Generate ();
use Crypt::Perl::PKCS10 ();

use HTTP::Tiny ();

# Used to report failed challenges.
use Data::Dumper;

use Net::ACME2::LetsEncrypt ();

use constant {
    _ECDSA_CURVE => 'secp384r1',
    CAN_WILDCARD => 0,
};

sub _finish_http_curl {
    my ($http) = @_;

    use AnyEvent;

    my $cv = AnyEvent->condvar();

    AnyEvent->idle( sub {
        $cv->() if !$http->handles();
    } );

}

sub run {
    my ($class) = @_;

    local $Promise::ES6::DETECT_MEMORY_LEAKS = 1;

    my $_test_key = Crypt::Perl::ECDSA::Generate::by_name(_ECDSA_CURVE())->to_pem_with_curve_name();

use lib '/Users/felipe/code/p5-Net-Curl-Promiser/lib';
require Net::Curl::Promiser::AnyEvent;
require Net::ACME2::Curl;

    my $promiser = Net::Curl::Promiser::AnyEvent->new();

    my $acme = Net::ACME2::LetsEncrypt->new(
        environment => 'staging',
        http_ua => Net::ACME2::Curl->new($promiser),
        key => $_test_key,
    );

    my $key_id_promise;

    #conditional is for if you want to modify this example to use
    #a pre-existing account.
    if ($acme->key_id()) {
        die "not for example";
    }
    else {
        $key_id_promise = $acme->get_terms_of_service()->then( sub {
            my $tos = shift;

            print "$/Indicate acceptance of the terms of service at:$/$/";
            print "\t" . $tos . $/ . $/;
            print "… by hitting ENTER now.$/";
            <>;

            my $acct_promise = $acme->create_account(
                termsOfServiceAgreed => 1,
            );

use Data::Dumper;
#print STDERR Dumper(acct_promise => $acct_promise);

            return $acct_promise;
        } );
    }

    my $authzs_ar;

    my (@domains, $order, $key, $csr);

    $key_id_promise->then( sub {
print "order done\n";
        @domains = $class->_get_domains();

        return $acme->create_order(
            identifiers => [ map { { type => 'dns', value => $_ } } @domains ],
        );
    } )->then( sub {
        $order = shift;

        return Promise::ES6->all(
            [ map { $acme->get_authorization($_) } $order->authorizations() ],
        );
    } )->then( sub {
        $authzs_ar = shift;

        my $valid_authz_count = 0;

        for my $authz_obj (@$authzs_ar) {
            my $domain = $authz_obj->identifier()->{'value'};

            if ($authz_obj->status() eq 'valid') {
                $valid_authz_count++;
                print "$/This account is already authorized on $domain.$/";
                next;
            }

            my $challenge = $class->_authz_handler($acme, $authz_obj);

            return $acme->accept_challenge($challenge);
        }
    } )->then( sub {
        my @promises;

        for my $authz (@$authzs_ar) {
            next if $authz->status() eq 'valid';

            push @promises, $acme->poll_authorization($authz)->then( sub {
                my $status = shift;

                my $name = $authz->identifier()->{'value'};
                substr($name, 0, 0, '*.') if $authz->wildcard();

                if ($status eq 'valid') {

                    print "$/“$name” has passed validation.$/";
                }
                elsif ($status eq 'pending') {
                    print "$/“$name”’s authorization is still pending …$/";
                }
                else {
                    if ($status eq 'invalid') {
                        my $challenge = $class->_get_challenge_from_authz($authz);
                        print Dumper($challenge);
                    }

                    die "$/“$name”’s authorization is in “$status” state.";
                }
            } );
        }

        if (@promises) {
            print "Waiting 1 second before polling authzs again …$/";

            sleep 1;

            return Promise::ES6->all(\@promises)->then(__SUB__);
        }

        return undef;
    } )->then( sub {
        ($key, $csr) = _make_key_and_csr_for_domains(@domains);

        print "Finalizing order …$/";

        return $acme->finalize_order($order, $csr)->then( sub {
            if ($order->status() ne 'valid') {
                print "Waiting 1 second before polling order again …$/";

                sleep 1;

                return $acme->poll_order($order)->then(__SUB__);
            }
        } );
    } )->then( sub {
        return $acme->get_certificate_chain($order);
    } )->then( sub {
        print "Certificate key:$/$key$/$/";

        print "Certificate chain:$/";

        print shift;
    } )->catch( sub {
        my $msg = shift;
        print STDERR "FAILURE: " . ( eval { $msg->get_message() } // $msg ) . $/;
    } );

    _finish_http_curl($promiser);

    return;
}

sub _get_challenge_from_authz {
    my ($class, $authz_obj) = @_;

    my $challenge_type = $class->_CHALLENGE_TYPE();

    my ($challenge) = grep { $_->type() eq $challenge_type } $authz_obj->challenges();

    if (!$challenge) {
        die "No “$challenge_type” challenge for “$authz_obj”!\n";
    }

    return $challenge;
}

sub _get_domains {
    my ($self) = @_;

    print $/;

    my @domains;
    while (1) {
        print "Enter a domain for the certificate (or ENTER if you’re done): ";
        my $d = <STDIN>;
        chomp $d;

        if (!defined $d || !length $d) {
            last if @domains;

            warn "Give at least one domain.$/";
        }
        else {
            if ($d =~ tr<*><> && !$self->CAN_WILDCARD) {
                warn "This authorization type can’t do wildcard!\n";
            }
            else {
                push( @domains, $d );
            }
        }
    }

    return @domains;
}

sub _make_key_and_csr_for_domains {
    my (@domains) = @_;

    Call::Context::must_be_list();

    #ECDSA is used here because it’s quick enough to run in pure Perl.
    #If you need/want RSA, look at Crypt::OpenSSL::RSA, and/or
    #install Math::BigInt::GMP (or M::BI::Pari) and use
    #Crypt::Perl::RSA::Generate. Or just do qx<openssl genrsa>. :)
    my $key = Crypt::Perl::ECDSA::Generate::by_name(_ECDSA_CURVE());

    my $pkcs10 = Crypt::Perl::PKCS10->new(
        key => $key,

        subject => [
            commonName => $domains[0],
        ],

        attributes => [
            [ 'extensionRequest',
                [ 'subjectAltName', map { ( dNSName => $_ ) } @domains ],
            ],
        ],
    );

    return ( $key->to_pem_with_curve_name(), $pkcs10->to_pem() );
}

1;
