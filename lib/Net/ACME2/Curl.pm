package Net::ACME2::Curl;

use strict;
use warnings;

use Promise::ES6 ();

use Net::Curl::Easy ();
use Net::Curl::Multi ();

use Net::ACME2::HTTP::Convert ();

sub new {
    my ($class, $promiser) = @_;

    return bless { _promiser => $promiser }, $class;
}

sub _get_ua_string {
    return ref(shift()); # XXX TODO FIXME
}

sub request {
    my ($self, $method, $url, $args_hr) = @_;

    $_ = q<> for my ($head, $body);

    my $easy = Net::Curl::Easy->new();
    $easy->setopt( Net::Curl::Easy::CURLOPT_USERAGENT(), $self->_get_ua_string() );
    $easy->setopt( Net::Curl::Easy::CURLOPT_URL(), $url );
    $easy->setopt( Net::Curl::Easy::CURLOPT_HEADERDATA(), \$head );
    $easy->setopt( Net::Curl::Easy::CURLOPT_FILE(), \$body );

    _assign_headers( $args_hr->{'headers'}, $easy );

    if ($method eq 'POST') {
        $easy->setopt( Net::Curl::Easy::CURLOPT_POST(), 1 );

        if (defined $args_hr->{'content'}) {
            $easy->setopt(
                Net::Curl::Easy::CURLOPT_COPYPOSTFIELDS(),
                $args_hr->{'content'},
            );
        }
    }
    elsif ($method ne 'GET') {
        die "bad method: [$method]";
    }

    return $self->{'_promiser'}->then(
        sub {
            return _imitate_http_tiny( shift(), $head, $body );
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
    )->then( sub {
        my ($resp) = @_;

        return Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2($method, $resp);
    } );
}

sub _imitate_http_tiny {
    my ($easy, $head, $body) = @_;

    my $status_code = $easy->getinfo( Net::Curl::Easy::CURLINFO_RESPONSE_CODE() );

    my %headers;
    for my $line ( split m<\x0d?\x0a>, $head ) {
        my ($name, $value) = split m<\s*:\s*>, $line;
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

    my %resp = (
        success => ($status_code >= 200) && ($status_code <= 299),
        url => $easy->getinfo( Net::Curl::Easy::CURLINFO_EFFECTIVE_URL() ),
        status => $status_code,
        #reason => ...,
        content => $body,
        headers => \%headers,
    );

    return \%resp;
}

sub _assign_headers {
    my ($hdrs_hr, $easy) = @_;

    if ($hdrs_hr && %$hdrs_hr) {
        my @hdr_strs;

        for my $name (keys %$hdrs_hr) {
            my $value = $hdrs_hr->{$name};

            die "Can’t handle $value as header!" if ref $value;

            push @hdr_strs, "$name: $value";
        }

        $easy->pushopt( Net::Curl::Easy::CURLOPT_HTTPHEADER(), \@hdr_strs );
    }

    return;
}

1;
