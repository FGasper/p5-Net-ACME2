package Net_ACME2_Example_Async;

use strict;
use warnings;

# Without __SUB__ we get memory leaks.
use feature 'current_sub';

use parent 'Net_ACME2_Example';

use FindBin;
use lib "$FindBin::Bin/../lib";

use Crypt::Perl::ECDSA::Generate ();
use Crypt::Perl::PKCS10 ();

use lib '/Users/felipe/code/p5-Net-Curl-Promiser/lib';

use AnyEvent;
require Net::Curl::Promiser::AnyEvent;

use Net::ACME2::Curl ();

# Used to report failed challenges.
use Data::Dumper;

use Net::ACME2::LetsEncrypt ();

use constant {
    _ECDSA_CURVE => 'secp384r1',
    CAN_WILDCARD => 0,
};

sub _finish_http_curl {
    my ($end_promise) = @_;

    my $cv = AnyEvent->condvar();

    $end_promise->finally($cv);

    $cv->recv();
}

sub run {
    my ($class) = @_;

    local $Promise::ES6::DETECT_MEMORY_LEAKS = 1;

    my $_test_key = Crypt::Perl::ECDSA::Generate::by_name(_ECDSA_CURVE())->to_pem_with_curve_name();

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

            # This isn’t very “async”, but oh well. :)
            <>;

            my $acct_promise = $acme->create_account(
                termsOfServiceAgreed => 1,
            );

            return $acct_promise;
        } );
    }

    my $authzs_ar;

    my (@domains, $order, $key, $csr);

    my $end_promise = $key_id_promise->then( sub {
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
        ($key, $csr) = $class->_make_key_and_csr_for_domains(@domains);

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

    _finish_http_curl($end_promise);

    return;
}

1;
