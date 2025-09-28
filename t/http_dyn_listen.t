#!/usr/bin/perl   #是perl 解释器的路径

# (C) Sergey Kandaurov

# Tests for nginx access module.

# At the moment only the new "unix:" syntax is tested (cf "all").

###############################################################################

use warnings; 

use strict;  

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;  
use Test::Nginx::Stream qw/ dgram /;
# use Data::Dumper;

###############################################################################



select STDERR; $| = 1;
select STDOUT; $| = 1;
eval { require IO::Socket::SSL; };


our $count = 1; 

my $t = Test::Nginx->new()->plan(10);
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
load_module %%njet_module_path%%/njt_app_sticky_module.so;
load_module %%njet_module_path%%/njt_dyn_ssl_module.so;
load_module %%njet_module_path%%/njt_http_vtsc_module.so;
load_module %%njet_module_path%%/njt_http_dyn_limit_module.so;
load_module  %%njet_module_path%%/njt_http_dyn_upstream_module.so;
load_module %%njet_module_path%%/njt_http_upstream_member_module.so;
load_module %%njet_module_path%%/njt_http_dyn_header_module.so;
load_module %%njet_module_path%%/njt_http_dyn_server_module.so;
load_module %%njet_module_path%%/njt_stream_dyn_server_module.so;

shared_slab_pool_size  100m;
cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 
error_log logs/error.log debug; 
events {
	worker_connections 1024; 
}


http {
    include mime.types;
    # log_format aaaa  '$request_time     $upstream_response_time     $upstream_connect_time';
    log_format aaaa '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log logs/access.log aaaa;


    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;
     server {
     server_name server-9000;
     listen 0.0.0.0:9000;

       location /{
            
                  return 200 "9000 ok\n";
       
      }
      }
      server {
     server_name server-9001;

     listen 0.0.0.0:9001 ;


       location /{
            
          proxy_pass https://127.0.0.1:7086;           
       
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
load_module %%njet_module_path%%/njt_stream_dyn_server_api_module.so;
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


$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost', '1.example.com', '2.example.com','3.example.com') {
  system('openssl req -x509 -new '
    . "-config $d/conf/openssl.conf -subj /CN=$name/ "
    . "-out $d/conf/$name.crt -keyout $d/conf/$name.key "
    . ">>$d/openssl.out 2>&1") == 0
    or die "Can't create certificate for $name: $!\n";
}

$t->create_common_configs($t);
$t->run();
sleep(2);

my $http_url = '/';  
#my $response = http_get($url);  
diag("Running query default http vs 1");
my $result1 =$t->get_with_port($http_url, 'localhost', 9000);

like($result1, qr/9000 ok/, 'default http vs ok');


my $json_payload_vs = '{
  "type": "add",
  "addr_port": "0.0.0.0:7084",
  "server_name": "server-27084",
  "server_body": "return 200 \"server-27084 ok!\";" 
}';  

my $r;

$r = http(<<EOF);
POST /api/v1/dyn_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_vs)]}

$json_payload_vs 

EOF

diag("Running add http vs 2");
like($r, qr/"code":0,"msg":"success./, 'post vs');
sleep(1);

diag("Running query new http vs 3");
my $result2 =$t->get_with_port($http_url, 'localhost', 7084);

like($result2, qr/server-27084 ok!/, 'new http vs ok');


diag("Running query del new http vs 4");

my $json_del_vs = '{
  "type": "del",
  "addr_port": "0.0.0.0:7084",
  "server_name": "server-27084"
}'; 

$r = http(<<EOF);
PUT /api/v1/dyn_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_del_vs)]}

$json_del_vs 

EOF

like($r, qr/"code":0,"msg":"success./, 'del new vs ok');

sleep(1);
diag("Running query del new http vs 5");
$result1 =$t->get_with_port($http_url, 'localhost', 9000);

like($result1, qr/9000 ok/, 'default http vs ok');


diag("Running query default http vs 6");
my $result5 =$t->get_with_port($http_url, 'localhost', 9000);

like($result5, qr/9000 ok/, 'default http vs ok');


my $json_payload_vs = '{
  "type": "add",
  "addr_port": "0.0.0.0:7086",
  "listen_option": "ssl",
  "server_name": "server-27086",
  "server_body": "ssl_certificate ./localhost.crt; ssl_certificate_key ./localhost.key; return 200 \"server-27086 ok!\";" 

}';  

my $r;

$r = http(<<EOF);
POST /api/v1/dyn_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_vs)]}

$json_payload_vs 

EOF

diag("Running add http vs 7");
like($r, qr/"code":0,"msg":"success./, 'post vs');
sleep(1);

diag("Running query new http ssl vs 8");
my $result2 =$t->get_with_port($http_url, 'localhost', 9001);

like($result2, qr/server-27086 ok!/, 'new http ssl vs ok');


diag("Running query del new http ssl vs 9");

my $json_del_vs = '{
  "type": "del",
  "addr_port": "0.0.0.0:7086",
  "server_name": "server-27086"
}'; 

$r = http(<<EOF);
PUT /api/v1/dyn_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_del_vs)]}

$json_del_vs 

EOF

like($r, qr/"code":0,"msg":"success./, 'del new vs ok');

sleep(1);
diag("Running query del new http vs 10");
$result1 =$t->get_with_port($http_url, 'localhost', 9000);

like($result1, qr/9000 ok/, 'default http vs ok');

