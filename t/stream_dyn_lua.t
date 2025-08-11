#!/usr/bin/perl
# (C) Sergey Kandaurov

# Tests for nginx access module.

# At the moment only the new "unix:" syntax is tested (cf "all").


# Tests for njet stream dynamic Lua module.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(3);
my $njet_module_path = set_njet_module_path();
diag "njet_module_path = $njet_module_path";
$t->{_expand_vars} = { njet_module_path => $njet_module_path };

$t->write_file_expand('njet.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
worker_processes auto;
cluster_name njet;
node_name node1;
error_log logs/error.log error;

helper ctrl %%njet_module_path%%/njt_helper_ctrl_module.so conf/njet_ctrl.conf;
helper broker %%njet_module_path%%/njt_helper_broker_module.so conf/mqtt.conf;

load_module %%njet_module_path%%/njt_stream_lua_module.so;
load_module %%njet_module_path%%/njt_stream_dyn_lua_module.so;

events {
    worker_connections 1024;
}

http {
}

stream {
    lua_package_path "$prefix/lualib/lib/?.lua;/usr/local/njet/modules/?.lua;$prefix/apps/?.lua;;";
    lua_package_cpath "$prefix/lualib/clib/?.so;;";

    server {
        listen 8001;
        preread_by_lua_block {
            njt.log(njt.ERR, "now in preread_by_lua")
        }
        content_by_lua_block {
            njt.say("testing")
        }
    }
}
EOF

$t->write_file_expand('njet_ctrl.conf', <<'EOF');
load_module %%njet_module_path%%/njt_http_sendmsg_module.so;
load_module %%njet_module_path%%/njt_ctrl_config_api_module.so;
load_module %%njet_module_path%%/njt_doc_module.so;

error_log logs/error_ctrl.log error;

events {
    worker_connections 1024;
}

http {
	        dyn_kv_conf       conf/ctrl_kv.conf;
        dyn_sendmsg_conf conf/iot-ctrl.conf;
    include mime.types;
    access_log off;

    server {
        listen 127.0.0.1:8080;

        location / {
            return 200 "njet control panel\n";
        }

        location /api {
            dyn_module_api;
        }

        location /doc {
            doc_api;
        }
    }
}
EOF

$t->create_common_configs($t);
$t->run() or die "Failed to start njet: $!";
sleep 2;
my $url = '/api/v1/config/stream_dyn_lua';

# Helper function for stream testing
use IO::Socket::INET;
sub stream_get {
    my ($host) = @_;
    my $socket = IO::Socket::INET->new(
        PeerAddr => $host,
        Proto    => 'tcp',
        Timeout  => 5
    ) or die "Cannot connect to $host: $!";
    my $data = '';
    while (my $line = <$socket>) {
        $data .= $line;
    }
    close $socket;
    return $data;
}

# Test 1: Verify existing stream Lua configuration
my $response = http_get($url);
like($response, qr/"content_by":".*?njt\.say\(\\"testing\\"\).*?"/s, 'get stream Lua config');


# Test 2: Post new stream Lua configuration
my $json_payload = '{
    "upstreams":[],"servers":[{"listens":["0.0.0.0:8001"],"serverNames":[""],"lua":{"content_by":"\n            njt.say(\"dynamic lua test\")\n        ","preread_by":"\n            njt.log(njt.ERR, \"now in preread_by_lua\")\n        "}}]
}';

my $r = http(<<EOF);
PUT /api/v1/config/stream_dyn_lua HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload)]}
Content-Type: application/json

$json_payload
EOF
like($r, qr/"msg":"success/, 'post stream Lua config');

# Test 3: Verify new Lua configuration is applied
my $stream_response = stream_get('127.0.0.1:8001');
like($stream_response, qr/dynamic lua test/, 'new stream Lua config applied')
