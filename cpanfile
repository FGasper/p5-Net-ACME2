requires 'autodie'                  => 0;
requires 'Call::Context'            => 0.02;
requires 'constant'                 => 1.23;
requires 'Crypt::Format'            => 0.06;
requires 'Crypt::Perl'              => 0.18;
requires 'HTTP::Tiny'               => 0.058;
requires 'HTTP::Tiny::UA::Response' => 0.004;
requires 'IO::Socket::SSL'          => 0;
requires 'JSON'                     => 2.9;
requires 'MIME::Base64'             => 3.11;
requires 'Module::Runtime'          => 0;
requires 'parent'                   => 0.225;
requires 'X::Tiny'                  => 0.12;

on 'test' => sub {
    requires 'File::Slurp'        => 0;
    requires 'Test::More'         => 1.0;
    requires 'Test::Deep'         => 0;
    requires 'Test::Exception'    => 0.40;
    requires 'Test::NoWarnings'   => 0;
    requires 'Test::FailWarnings' => 0;
    requires 'HTTP::Status'       => 0;
};
