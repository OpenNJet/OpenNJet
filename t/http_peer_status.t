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


my $t = Test::Nginx->new()->plan(8);
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

shared_slab_pool_size  100m;
cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 

events {
	worker_connections 1024; 
}

stream {

        upstream ctl_upstream {
                zone ctl_upstream 10M;
                hash $remote_addr consistent;
                server [2408:8606:8400:30a:6::1a]:990;
        }


        upstream  mqtt_upstream{
                zone mqtt_upstream 10M;
                server 127.0.0.1:1894 max_fails=3 fail_timeout=30s;
        }

        server {
                listen 9002 udp mesh;
                proxy_pass 192.168.40.136:9004;
        }
}


http {
    include mime.types;
    # log_format aaaa  '$request_time     $upstream_response_time     $upstream_connect_time';
    log_format aaaa '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log logs/access.log aaaa;


     upstream back{
                zone back 10M;
                #server 192.168.40.136:8090;
                server 127.0.0.1:8008;           #real server
                server 127.0.0.1:8009;           #real server
     }

   map $arg_a $testv {
        default    00;
         aa        11;
         bb        22;
         cc        33;
        
       }

     server {
     server_name localhost;
     listen 127.0.0.1:8082;

       location / {
            
                  return 200 "map test,mapped value is ${testv} \n";
       
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

cluster_name helper; 
node_name node1; 
error_log logs/error_ctrl.log info; 
events { 
	worker_connections 1024; 
}

http { 
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
$t->run();
sleep 2;
my $json_url = '/shm/format/json';  
#my $response = http_get($url);  
diag("Running /shm/format/json format");
like(http_get($json_url), qr/"upstream":"back","server":"127.0.0.1:8008","status":1/, 'peer8008 status json format ok');
like(http_get($json_url), qr/"upstream":"back","server":"127.0.0.1:8009","status":1/, 'peer8008 status json format ok');
like(http_get($json_url), qr/"upstream":"ctl_upstream","server":"\[2408:8606:8400:30a:6::1a]:990","status":1/, 'peer990 status json format ok');
like(http_get($json_url), qr/"upstream":"mqtt_upstream","server":"127.0.0.1:1894","status":1/, 'peer1894 status json format ok');


diag("Running /shm/format/prometheus format");
my $pro_url = '/shm/format/prometheus';  
like(http_get($pro_url), qr/name="back", server="127.0.0.1:8008", type="http"/, 'peer8008 status prometheus format ok');
like(http_get($pro_url), qr/name="back", server="127.0.0.1:8009", type="http"/, 'peer8009 status prometheus format ok');
like(http_get($pro_url), qr/name="ctl_upstream", server="\[2408:8606:8400:30a:6::1a]:990"/, 'peer990 status prometheus format ok');
like(http_get($pro_url), qr/name="mqtt_upstream", server="127.0.0.1:1894", type="stream"/, 'peer1894 status prometheus format ok');

#diag("Running /shm/format/html format");
#like(http_get($url), qr/"server": "127.0.0.1:8008"/, 'peer status html format ok');
