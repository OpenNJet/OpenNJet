# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(3);

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

#no_diff();

__DATA__

=== TEST 1: base64url encode
--- config
    location /bar {
        set_encode_base64url $out "?b><d?";
        echo $out;
    }
--- request
    GET /bar
--- response_body
P2I-PGQ_



=== TEST 2: base64url decode
--- config
    location /bar {
        set_decode_base64url $out "P2I-PGQ_";
        echo $out;
    }
--- request
    GET /bar
--- response_body
?b><d?
