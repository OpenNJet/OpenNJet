#!/usr/bin/perl   #是perl 解释器的路径

# (C) Sergey Kandaurov

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
our $count = 1; 

my $t = Test::Nginx->new()->plan(12);
my $njet_module_path = set_njet_module_path(); 
warn "--------------njet_module_path = $njet_module_path";
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
load_module  %%njet_module_path%%/njt_http_dyn_upstream_module.so;
load_module %%njet_module_path%%/njt_http_upstream_member_module.so;
load_module %%njet_module_path%%/njt_http_dyn_header_module.so;
load_module %%njet_module_path%%/njt_http_dyn_server_module.so;

shared_slab_pool_size  100m;
cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 
error_log logs/error.log debug; 
events {
	worker_connections 1024; 
}

stream {

        upstream tcp_upstream {
                zone tcp_upstream 10M;
                server 127.0.0.1:9001;
        }

        upstream udp_upstream {
                zone udp_upstream 10M;
                server 127.0.0.1:9002;
        }

        upstream mysql_upstream {
                zone udp_upstream 10M;
                server 127.0.0.1:9003;
        }
}


http {
    %%TEST_GLOBALS_HTTP%%

      upstream http_upstream {
              zone http_upstream 10M;
              server 127.0.0.1:9004;
      }


    server {
        listen       127.0.0.1:8008;
        server_name  localhost;

        location /ticket {
            return 200 "http_response";
        }
    }
}
		
EOF

$t->write_file_expand('njet_ctrl.conf', <<'EOF');

load_module %%njet_module_path%%/njt_http_sendmsg_module.so; 
load_module %%njet_module_path%%/njt_ctrl_config_api_module.so; 
load_module %%njet_module_path%%/njt_helper_health_check_module.so; 
load_module %%njet_module_path%%/njt_http_upstream_api_module.so; 
load_module %%njet_module_path%%/njt_http_location_api_module.so; 
load_module %%njet_module_path%%/njt_doc_module.so; 
load_module %%njet_module_path%%/njt_http_vtsd_module.so; 
load_module %%njet_module_path%%/njt_http_shm_status_module.so;
load_module %%njet_module_path%%/njt_http_dyn_upstream_module.so;
load_module %%njet_module_path%%/njt_http_dyn_upstream_api_module.so;
load_module %%njet_module_path%%/njt_http_dyn_server_api_module.so;

cluster_name helper; 
node_name node1; 
error_log logs/error_ctrl.log debug; 
events { 
	worker_connections 1024; 
}

http { 
        dyn_kv_conf       conf/ctrl_kv.conf;
	dyn_sendmsg_conf conf/iot-ctrl.conf; 
	config_req_pool_size 1000; 
	access_log logs/access_ctrl.log combined; 
	include mime.types; 
 
	server { 
  server_name localhost;
		listen 127.0.0.1:8080; 
    
    
		 location /api {
        dyn_module_api;
    }

        location /shm {
            shm_status_display;
        }

    location /doc {
        doc_api;
     }
		location /metrics { 
            vhost_traffic_status_display; 
			vhost_traffic_status_display_format html;
      
		} 

	} 
}
		
EOF


# my $d = $t->testdir();
$t->create_common_configs($t);
# $t->run_daemon(\&tcp_daemon, port(9001), $t);
# $t->run_daemon(\&udp_daemon, port(9002), $t);
$t->run();

# sub tcp_daemon {
#         my ($port, $t) = @_;

#         my ($data, $recv_data);
#         my $socket = IO::Socket::INET->new(
#                 LocalAddr    => '127.0.0.1',
#                 LocalPort    => $port,
#                 Proto        => 'tcp',
#         )
#                 or die "Can't create listening socket: $!\n";

#         local $SIG{PIPE} = 'IGNORE';

#         # signal we are ready

#         while (1) {
#                 $socket->recv($recv_data, 65536);
#                 $socket->send("tcp_response");
#         }
# }

# sub udp_daemon {
#         my ($port, $t) = @_;

#         my ($data, $recv_data);
#         my $socket = IO::Socket::INET->new(
#                 LocalAddr    => '127.0.0.1',
#                 LocalPort    => $port,
#                 Proto        => 'udp',
#         )
#                 or die "Can't create listening socket: $!\n";

#         local $SIG{PIPE} = 'IGNORE';

#         # signal we are ready

#         while (1) {
#                 $socket->recv($recv_data, 65536);
#                 $socket->send("udp_response");
#         }
# }


#add stcp hc
my $tcp_hc_json_url = '/api/v1/hc/stcp/tcp_upstream'; 

my $json_payload_stcp = '{
  "interval": "5s",
  "jitter": "1s",
  "timeout": "5s",
  "passes": 1,
  "fails": 1,
  "stream": {
    "send": "tcp_send",
    "expect": "tcp_response"
  }
}';

my $res_stcp = http(<<EOF);
POST $tcp_hc_json_url HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_stcp)]}

$json_payload_stcp 

EOF

diag("Running stcp hc add");
like($res_stcp, qr/"msg": "success"/, 'stcp hc add ok');

sleep 2;

#query stcp hc
diag("Running stcp hc get");
my $response = $t->get_with_port($tcp_hc_json_url, 'localhost', 8080);

like($response, qr/expect/, 'stcp hc get ok');

#delete stcp hc
diag("Running stcp hc delete");
my $res_del_stcp = http(<<EOF);
DELETE $tcp_hc_json_url HTTP/1.1
Host: localhost
Connection: close

EOF
like($res_del_stcp, qr/"msg": "success"/, 'stcp hc delete ok');


#add sudp hc
my $udp_hc_json_url = '/api/v1/hc/sudp/udp_upstream'; 

my $json_payload_sudp = '{
  "interval": "5s",
  "jitter": "1s",
  "timeout": "5s",
  "passes": 1,
  "fails": 1,
  "stream": {
    "send": "udp_send",
    "expect": "udp_response"
  }
}';

my $res_sudp = http(<<EOF);
POST $udp_hc_json_url HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_sudp)]}

$json_payload_sudp

EOF

diag("Running sudp hc add");
like($res_sudp, qr/"msg": "success"/, 'sudp hc add ok');

sleep 2;

#query sudp hc
diag("Running sudp hc get");
$response = $t->get_with_port($udp_hc_json_url, 'localhost', 8080);

like($response, qr/expect/, 'sudp hc get ok');


#delete sudp hc
diag("Running sudp hc delete");
my $res_del_sudp = http(<<EOF);
DELETE $udp_hc_json_url HTTP/1.1
Host: localhost
Connection: close

EOF
like($res_del_sudp, qr/"msg": "success"/, 'sudp hc delete ok');


#add smysql hc
my $mysql_hc_json_url = '/api/v1/hc/smysql/mysql_upstream'; 

my $json_payload_smysql = '{
  "interval": "5s",
  "jitter": "1s",
  "timeout": "5s",
  "passes": 1,
  "fails": 1,
  "sql": {
    "select": "select 1",
    "useSsl": true,
    "user": "root",
    "password": "*****",
    "db": "db"
  }
}';

my $res_smysql = http(<<EOF);
POST $mysql_hc_json_url HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_smysql)]}

$json_payload_smysql

EOF

diag("Running smysql hc add");
like($res_smysql, qr/"msg": "success"/, 'smysql hc add ok');

sleep 2;

#query smysql hc
diag("Running smysql hc get");
$response = $t->get_with_port($mysql_hc_json_url, 'localhost', 8080);

like($response, qr/select/, 'smysql hc get ok');


#delete smysql hc
diag("Running smysql hc delete");
my $res_del_smysql = http(<<EOF);
DELETE $mysql_hc_json_url HTTP/1.1
Host: localhost
Connection: close

EOF
like($res_del_smysql, qr/"msg": "success"/, 'smysql hc delete ok');



#add http hc
my $http_hc_json_url = '/api/v1/hc/http/http_upstream'; 

my $json_payload_http = '{
  "interval": "5s",
  "jitter": "1s",
  "timeout": "5s",
  "passes": 1,
  "fails": 1,
  "http": {
    "uri": "/",
    "status": "200"
  }
}';

my $res_http = http(<<EOF);
POST $http_hc_json_url HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_http)]}

$json_payload_http

EOF

diag("Running http hc add");
like($res_http, qr/"msg": "success"/, 'http hc add ok');

sleep 2;

#query http hc
diag("Running http hc get");
$response = $t->get_with_port($http_hc_json_url, 'localhost', 8080);

like($response, qr/"status":"200"/, 'http hc get ok');

#delete http hc
diag("Running http hc delete");
my $res_del_http = http(<<EOF);
DELETE $http_hc_json_url HTTP/1.1
Host: localhost
Connection: close

EOF


like($res_del_http, qr/"msg": "success"/, 'http hc delete ok');


###############################################################################
