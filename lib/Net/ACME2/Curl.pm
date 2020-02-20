package Net::ACME2::Curl;

use strict;
use warnings;

use Promise::ES6 ();

use Net::Curl::Easy ();
use Net::Curl::Multi ();

use Net::ACME2::HTTP::Convert ();

# blegh
use Net::ACME2 ();

sub new {
    my ($class, $promiser) = @_;

    return bless { _promiser => $promiser }, $class;
}

sub _get_ua_string {
    my ($self) = @_;

    return ref($self) . " $Net::ACME2::VERSION";
}

sub request {
    my ($self, $method, $url, $args_hr) = @_;

    my $easy = _xlate_http_tiny_request_to_net_curl_easy($method, $url, $args_hr);

    $easy->setopt( Net::Curl::Easy::CURLOPT_USERAGENT(), $self->_get_ua_string() );

    $_ = q<> for @{$easy}{ qw( _head _body ) };

    $easy->setopt( Net::Curl::Easy::CURLOPT_HEADERDATA(), \$easy->{'_head'} );
    $easy->setopt( Net::Curl::Easy::CURLOPT_FILE(), \$easy->{'_body'} );

    my $p1 = $self->{'_promiser'}->add_handle($easy)->then(
        sub {
            my ($easy) = @_;

            return _imitate_http_tiny( shift(), @{$easy}{'_head', '_body'} );
        },
        sub {
            return {
                success => 0,
                url => $easy->getinfo( Net::Curl::Easy::CURLINFO_EFFECTIVE_URL() ),
                status => 599,
                reason => q<>,
                content => q<> . shift(),
                headers => {},
            };
        },
    );

    return $p1->then( sub {
        my ($resp) = @_;

        return Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2($method, $resp);
    } );
}

# curl response -> HTTP::Tiny response
sub _imitate_http_tiny {
    my ($easy, $head, $body) = @_;

    my $status_code = $easy->getinfo( Net::Curl::Easy::CURLINFO_RESPONSE_CODE() );

    my $reason;

    my %headers;
    for my $line ( split m<\x0d?\x0a>, $head ) {
        if (defined $reason) {
            my ($name, $value) = split m<\s*:\s*>, $line, 2;
            $name =~ tr<A-Z><a-z>;

            if (exists $headers{$name}) {
                if (ref $headers{$name}) {
                    push @{$headers{$name}}, $value;
                }
                else {
                    $headers{$name} = [ $headers{$name}, $value ];
                }
            }
            else {
                $headers{$name} = $value;
            }
        }
        else {
            if ( $line =~ m<.+? \s+ .+? \s+ (.*)>x ) {
                $reason = $1;
            }
            else {
                $reason = q<>;
                warn "Unparsable first header line: [$line]\n";
            }
        }
    }

    my %resp = (
        success => ($status_code >= 200) && ($status_code <= 299),
        url => $easy->getinfo( Net::Curl::Easy::CURLINFO_EFFECTIVE_URL() ),
        status => $status_code,
        reason => $reason,
        content => $body,
        headers => \%headers,
    );

    return \%resp;
}

# HTTP::Tiny request -> curl request
sub _xlate_http_tiny_request_to_net_curl_easy {
    my ($method, $url, $args_hr) = @_;

    my $easy = Net::Curl::Easy->new();

    # $easy->setopt( Net::Curl::Easy::CURLOPT_VERBOSE(), 1 );

    $easy->setopt( Net::Curl::Easy::CURLOPT_URL(), $url );

    _assign_headers( $args_hr->{'headers'}, $easy );

    if ($method eq 'POST') {
        $easy->setopt( Net::Curl::Easy::CURLOPT_POST(), 1 );

        if (defined $args_hr->{'content'} && length $args_hr->{'content'}) {
            $easy->setopt(
                Net::Curl::Easy::CURLOPT_POSTFIELDSIZE(),
                length $args_hr->{'content'},
            );
            $easy->setopt(
                Net::Curl::Easy::CURLOPT_COPYPOSTFIELDS(),
                $args_hr->{'content'},
            );
        }
    }
    elsif ($method eq 'HEAD') {

        # e.g., HEAD
        $easy->setopt( Net::Curl::Easy::CURLOPT_NOBODY(), 1 );
    }
    elsif ($method ne 'GET') {
        die "Bad HTTP method: [$method]";
    }

    return $easy;
}

sub _assign_headers {
    my ($hdrs_hr, $easy) = @_;

    if ($hdrs_hr && %$hdrs_hr) {
        my @hdr_strs;

        for my $name (keys %$hdrs_hr) {
            my $value = $hdrs_hr->{$name};

            if ( (ref($value) || q<a>)->isa('ARRAY') ) {
                push @hdr_strs, "$name: $_" for @$value;
            }
            elsif (ref $value) {
                die "Can’t handle $value as header!" if ref $value;
            }
            else {
                push @hdr_strs, "$name: $value";
            }
        }

        $easy->pushopt( Net::Curl::Easy::CURLOPT_HTTPHEADER(), \@hdr_strs );
    }

    return;
}

1;
