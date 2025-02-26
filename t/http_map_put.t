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


my $t = Test::Nginx->new()->plan(3);
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

cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 

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
my $url = '/api/v1/config/http_dyn_map';  
my $response = http_get($url);  
diag("Running test 1");
like(http_get($url), qr/"valueFrom":"cc","valueTo":"33"/, 'get map');




my $json_payload = '{  
  "maps": [  
    {  
      "keyFrom": "$host",  
      "keyTo": "$zzz",  
      "type":  "add",  
      "values": [  
        {  
          "valueFrom": "/www1",  
          "valueTo": "g12"  
        },  
        {  
          "valueFrom": "/www2",  
          "valueTo": "g2"  
        }  
      ],  
      "isVolatile": true,  
      "hostnames": false  
    }  
  ]  
}';  

my $r;

$r = http(<<EOF);
PUT /api/v1/config/http_dyn_map HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload)]}

$json_payload 

EOF
diag("Running test 2");
like($r, qr/"code":0,"msg":"success./, 'put map');



# 函数定义在测试脚本中
# sub get_with_port($;%) {
#     my ($host, $port) = @_;   
#     my $r = http_get(
#         '/?a=bb',
#         ( 
#             'Host' => $host || 'localhost', 
#             'port' => $port,
#             'SSL' => 0  # 禁用 SSL
#         )
#     );
#     return $r;
# }
#my $response2 = get_with_port('localhost', 8081);
my $response2 =$t->get_with_port('/?a=bb', 'localhost', 8082);
like($response2, qr/map test,mapped value is 22/, '响应内容应为 22');
