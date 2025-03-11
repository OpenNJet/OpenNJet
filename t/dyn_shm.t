#!/usr/bin/perl   #是perl 解释器的路径

# (C) Sergey Kandaurov
# (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.

# Tests for nginx access module.

# At the moment only the new "unix:" syntax is tested (cf "all").

###############################################################################

use warnings;

use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
# use Data::Dumper;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;


my $t = Test::Nginx->new()->plan(45);
my $njet_module_path = set_njet_module_path();
warn "\n--------------njet_module_path = $njet_module_path";
$t->{_expand_vars} = {
    njet_module_path => $njet_module_path
};

$t->write_file_expand('njet.conf', <<'EOF');

%%TEST_GLOBALS%%
daemon off;
helper broker %%njet_module_path%%/njt_helper_broker_module.so conf/mqtt.conf;
helper ctrl %%njet_module_path%%/njt_helper_ctrl_module.so conf/njet_ctrl.conf;

load_module  %%njet_module_path%%/njt_http_dyn_map_module.so;
load_module %%njet_module_path%%/njt_agent_dynlog_module.so;
load_module %%njet_module_path%%/njt_http_location_module.so;

load_module %%njet_module_path%%/njt_dyn_ssl_module.so;
load_module %%njet_module_path%%/njt_http_vtsc_module.so;
load_module %%njet_module_path%%/njt_http_dyn_limit_module.so;
load_module %%njet_module_path%%/njt_http_dyn_upstream_module.so;

cluster_name helper;
node_name node1;
worker_processes 1;
user root;

events {
	worker_connections 1024;
}

shared_slab_pool_size  100m;
shm_status on;

http {
    include mime.types;
    server {
       server_name localhost;
       listen 127.0.0.1:8082;

       location / {
                  return 200 "OK";
       }
    }

}

EOF

$t->write_file_expand('njet_ctrl.conf', <<'EOF');

load_module %%njet_module_path%%/njt_http_sendmsg_module.so;
load_module  %%njet_module_path%%/njt_http_dyn_upstream_module.so;
load_module %%njet_module_path%%/njt_ctrl_config_api_module.so;
load_module %%njet_module_path%%/njt_http_upstream_api_module.so;
load_module %%njet_module_path%%/njt_http_location_api_module.so;
load_module %%njet_module_path%%/njt_doc_module.so;
load_module %%njet_module_path%%/njt_http_lua_module.so;
load_module %%njet_module_path%%/njt_http_dyn_upstream_api_module.so;
load_module %%njet_module_path%%/njt_helper_health_check_module.so;
load_module %%njet_module_path%%/njt_http_shm_status_module.so;
load_module %%njet_module_path%%/njt_http_shm_api_module.so;
events {
    worker_connections  1024;
}
error_log         logs/error_ctrl.log info;

http {
    dyn_sendmsg_conf  conf/iot-ctrl.conf;
    #dyn_kv_conf       conf/ctrl_kv.conf;
    access_log        logs/access_ctrl.log combined;

    include           mime.types;

    server {
        listen       8081;
	     keepalive_timeout 0;

        location /api {
             dyn_module_api;

        }
	 location /doc {
        doc_api;
    }
	  location /report/ {
            root html;
        }
         location /ws {
          proxy_pass http://127.0.0.1:7890;
        }
	 location /shm {
            shm_status_display;
        }

        location /metrics {
            #vhost_traffic_status_display;
            #vhost_traffic_status_display_format html;
        }
	location /lua {
	    content_by_lua_block {
               smartl7.say("njet control panel")
	}
	}
  }

}

EOF


$t->create_common_configs($t);
sleep 2;
$t->run();
sleep 2;

diag("Running tests for dyn shared memory ");

# test njet works fine
my $resp_ok =$t->get_with_port('/', 'localhost', 8082);
like($resp_ok, qr/OK/, 'simple service ok');

# json statistics correct
my $response2 =$t->get_with_port('/shm/format/json', 'localhost', 8081);
like($response2, qr/"total_zone_count":3,"total_static_zone_count":1,"total_static_zone_pool_count":1/, 'json static zone count 1');
like($response2, qr/"total_dyn_zone_count":2,"total_dyn_zone_pool_count":2/, 'json dynamic zone count 1');

# prometheus statistics correct
my $response3 =$t->get_with_port('/shm/format/prometheus', 'localhost', 8081);
like($response3, qr/njet_shm_total\{type="zone_count"\} 3/, 'prometheus total zone count 1');
like($response3, qr/njet_shm_total\{type="static_zone_count"\} 1/, 'prometheus total zone count 1');
like($response3, qr/njet_shm_total\{type="dynamic_zone_count"\} 2/, 'prometheus dynamic zone count 1');

# get static zone autoscale attribute
my $zone_get1 = $t->get_with_port('/api/v1/shm/get/static/api_dy_server', 'localhost', 8081);
like($zone_get1, qr/"code":0,"msg":"zone autoscale is unset"/, 'get zone status 1');

# set static zone autoscale attribute
my $zone_set1 = http(<<EOF, ('port' => 8081));
PUT /api/v1/shm/set/static/api_dy_server HTTP/1.0

EOF
like($zone_set1, qr/"code":0/, 'set zone status 1');

# unset static zone autoscale attribute
my $zone_unset1 = http(<<EOF, ('port' => 8081));
PUT /api/v1/shm/unset/static/api_dy_server HTTP/1.0

EOF
like($zone_unset1, qr/"code":0/, 'unset zone status 1');
# set for unexist static zone
my $zone_set_unexist = http(<<EOF, ('port' => 8081));
PUT /api/v1/shm/get/static/log_zone HTTP/1.0

EOF
like($zone_set_unexist, qr/"code":4/, 'get unexist zone status 1');

# set for unexist dynamic zone
my $zone_set_unexist_dyn = http(<<EOF, ('port' => 8081));
PUT /api/v1/shm/get/static/log_zone HTTP/1.0

EOF
like($zone_set_unexist_dyn, qr/"code":4/, 'get unexist dynamic zone status 1');

# add one dynamic zone
diag("add a dynamic zone");
my %extra = (
    'port' => 8081,
);

my $json_add_zone_payload = '{
   "type": "add",
   "upstream_name": "upstream-90",
   "upstream_body": "zone upstream-90-zone 10m"
 }';

my $response5 = http(<<EOF, %extra);
POST /api/v1/dyn_ups HTTP/1.0
Host: 127.0.0.1
accept: */*
Content-Type: application/json
Content-Length: @{[length($json_add_zone_payload)]}

$json_add_zone_payload;

EOF

like($response5, qr/{"code":0,"msg":"success."}/, 'add upstream 1');

# json statistics correct
my $response6 =$t->get_with_port('/shm/format/json', 'localhost', 8081);
like($response6, qr/"total_zone_count":4,"total_static_zone_count":1,"total_static_zone_pool_count":1/, 'json static zone count 2');
like($response6, qr/"total_dyn_zone_count":3,"total_dyn_zone_pool_count":3/, 'json dynamic zone count 2');

# prometheus statistics correct
my $response7 =$t->get_with_port('/shm/format/prometheus', 'localhost', 8081);
like($response7, qr/njet_shm_total\{type="zone_count"\} 4/, 'prometheus total zone count 2');
like($response7, qr/njet_shm_total\{type="static_zone_count"\} 1/, 'prometheus total zone count 2');
like($response7, qr/njet_shm_total\{type="dynamic_zone_count"\} 3/, 'prometheus dynamic zone count 2');

# get dynamic zone autoscale attribute
my $zone_get2 = $t->get_with_port('/api/v1/shm/get/dynamic/upstream-90-zone', 'localhost', 8081);
like($zone_get2, qr/"code":0,"msg":"zone autoscale is unset"/, 'get dynamic zone status 2');

# set dynamic zone autoscale attribute
my $zone_set2 = http(<<EOF, ('port' => 8081));
PUT /api/v1/shm/set/dynamic/upstream-90-zone HTTP/1.0

EOF
like($zone_set2, qr/"code":0/, 'set zone status 1');

# unset dynamic zone autoscale attribute
my $zone_unset2 = http(<<EOF, ('port' => 8081));
PUT /api/v1/shm/unset/dynamic/upstream-90-zone HTTP/1.0

EOF
like($zone_unset2, qr/"code":0/, 'unset zone status 1');

# del dynamic zone
my $del_payload = '{
  "type": "del",
  "upstream_name": "upstream-90"
}';

my $zone_del = http(<<EOF, ('port' => 8081));
PUT /api/v1/dyn_ups HTTP/1.0
Host: localhost
Connection: close
Content-Length: @{[length($del_payload)]}

$del_payload

EOF
like($zone_del, qr/"code":0,"msg":"success/, 'del zone status 1');
# json statistics correct
my $resp1 =$t->get_with_port('/shm/format/json', 'localhost', 8081);
like($resp1, qr/"total_zone_count":3,"total_static_zone_count":1,"total_static_zone_pool_count":1/, 'json static zone count 3');
like($resp1, qr/"total_dyn_zone_count":2,"total_dyn_zone_pool_count":2/, 'json dynamic zone count 3');

# prometheus statistics correct
my $resp2 =$t->get_with_port('/shm/format/prometheus', 'localhost', 8081);
like($resp2, qr/njet_shm_total\{type="zone_count"\} 3/, 'prometheus total zone count 3');
like($resp2, qr/njet_shm_total\{type="static_zone_count"\} 1/, 'prometheus total zone count 3');
like($resp2, qr/njet_shm_total\{type="dynamic_zone_count"\} 2/, 'prometheus dynamic zone count 3');

sleep 1;
# reload
diag('reload');
$t->reload();
sleep 1;

# add one dynamic zone
diag("add a same dynamic zone again");
my $response8 = http(<<EOF, %extra);
POST /api/v1/dyn_ups HTTP/1.0
Host: 127.0.0.1
accept: */*
Content-Type: application/json
Content-Length: @{[length($json_add_zone_payload)]}

$json_add_zone_payload;

EOF

like($response8, qr/{"code":0,"msg":"success."}/, 'add upstream 1');

# json statistics correct
my $response9 =$t->get_with_port('/shm/format/json', 'localhost', 8081);
like($response9, qr/"total_zone_count":4,"total_static_zone_count":1,"total_static_zone_pool_count":1/, 'json static zone count 4');
like($response9, qr/"total_dyn_zone_count":3,"total_dyn_zone_pool_count":3/, 'json dynamic zone count 4');

# prometheus statistics correct
my $response10 =$t->get_with_port('/shm/format/prometheus', 'localhost', 8081);
like($response10, qr/njet_shm_total\{type="zone_count"\} 4/, 'prometheus total zone count 4');
like($response10, qr/njet_shm_total\{type="static_zone_count"\} 1/, 'prometheus total zone count 4');
like($response10, qr/njet_shm_total\{type="dynamic_zone_count"\} 3/, 'prometheus dynamic zone count 4');

sleep 1;
# reload
diag('reload');
$t->reload();
sleep 1;

# del dynamic zone
my $zone_del_2 = http(<<EOF, ('port' => 8081));
PUT /api/v1/dyn_ups HTTP/1.0
Host: localhost
Connection: close
Content-Length: @{[length($del_payload)]}

$del_payload

EOF

# add one dynamic zone (will remove zones marked del)
diag("add a same dynamic zone again");
my $response888 = http(<<EOF, %extra);
POST /api/v1/dyn_ups HTTP/1.0
Host: 127.0.0.1
accept: */*
Content-Type: application/json
Content-Length: @{[length($json_add_zone_payload)]}

$json_add_zone_payload;

EOF

# del dynamic zone
my $zone_del_3 = http(<<EOF, ('port' => 8081));
PUT /api/v1/dyn_ups HTTP/1.0
Host: localhost
Connection: close
Content-Length: @{[length($del_payload)]}

$del_payload

EOF
like($zone_del_2, qr/"code":0,"msg":"success/, 'del zone status after reload');
# json statistics correct
my $resp11 =$t->get_with_port('/shm/format/json', 'localhost', 8081);
like($resp11, qr/"total_zone_count":3,"total_static_zone_count":1,"total_static_zone_pool_count":1/, 'json static zone count 5');
like($resp11, qr/"total_dyn_zone_count":2,"total_dyn_zone_pool_count":2/, 'json dynamic zone count 5');

# prometheus statistics correct
my $resp22 =$t->get_with_port('/shm/format/prometheus', 'localhost', 8081);
like($resp22, qr/njet_shm_total\{type="zone_count"\} 3/, 'prometheus total zone count 5');
like($resp22, qr/njet_shm_total\{type="static_zone_count"\} 1/, 'prometheus total zone count 5');
like($resp22, qr/njet_shm_total\{type="dynamic_zone_count"\} 2/, 'prometheus dynamic zone count 5');


# add one dynamic zone
diag("add a same dynamic zone again after reload");
my $response88 = http(<<EOF, %extra);
POST /api/v1/dyn_ups HTTP/1.0
Host: 127.0.0.1
accept: */*
Content-Type: application/json
Content-Length: @{[length($json_add_zone_payload)]}

$json_add_zone_payload;

EOF

like($response88, qr/{"code":0,"msg":"success."}/, 'add upstream 1');

# json statistics correct
my $response11 =$t->get_with_port('/shm/format/json', 'localhost', 8081);
like($response11, qr/"total_zone_count":4,"total_static_zone_count":1,"total_static_zone_pool_count":1/, 'json static zone count 6');
like($response11, qr/"total_dyn_zone_count":3,"total_dyn_zone_pool_count":3/, 'json dynamic zone count 6');

# prometheus statistics correct
my $response12 =$t->get_with_port('/shm/format/prometheus', 'localhost', 8081);
like($response12, qr/njet_shm_total\{type="zone_count"\} 4/, 'prometheus total zone count 6');
like($response12, qr/njet_shm_total\{type="static_zone_count"\} 1/, 'prometheus total zone count 6');
like($response12, qr/njet_shm_total\{type="dynamic_zone_count"\} 3/, 'prometheus dynamic zone count 6');
# test njet works fine
my $response13 =$t->get_with_port('/', 'localhost', 8082);
like($response13, qr/OK/, 'simple service ok');

# sleep 50000;
# end of test
