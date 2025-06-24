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


my $t = Test::Nginx->new()->plan(25);
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
load_module %%njet_module_path%%/njt_http_sticky_module.so;

shared_slab_pool_size  100m;
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


    upstream back_ip_hash{
        sticky     hash=$binary_remote_addr expires=900s;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_url{
        sticky     hash=$request_uri expires=900s;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_arg{
        sticky     hash=$arg_aaa expires=900s;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_header{
        sticky     hash=$http_test expires=900s;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_learn{
        sticky learn;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_default{
        sticky;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_hash_md5{
        sticky hash=md5;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }
    

    upstream back_hash_sha1{
        sticky hash=sha1;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_hmac_md5{
        sticky hmac=md5 hmac_key=secret;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_hmac_sha1{
        sticky hmac=sha1 hmac_key=secret;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_domain{
        sticky domain=.example.com;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_path{
        sticky path=/example;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_expires{
        sticky expires=1h;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_text_md5{
        sticky text=md5;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_text_sha1{
        sticky text=sha1;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_text_raw{
        sticky text=raw;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_no_fallback{
        sticky no_fallback;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_secure{
        sticky secure;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }

    upstream back_httponly{
        sticky httponly;

        server 127.0.0.1:8008;           #real server
        server 127.0.0.1:8009;           #real server
    }


    server {
      listen       8010;

      location / {
            proxy_pass http://back_ip_hash;
      }
    }

    server {
      listen       8011;

      location / {
            proxy_pass http://back_url;
      }
    }

    server {
      listen       8012;

      location / {
            proxy_pass http://back_arg;
      }
    }

    server {
      listen       8013;

      location / {
            proxy_pass http://back_header;
      }
    }
    
    server {
      listen       8014;

      location / {
            proxy_pass http://back_learn;
      }
    }

    server {
      listen       8015;

      location / {
            proxy_pass http://back_default;
      }
    }

    server {
      listen       8016;

      location / {
            proxy_pass http://back_hash_md5;
      }
    }

    server {
      listen       8017;

      location / {
            proxy_pass http://back_hash_sha1;
      }
    }


    server {
      listen       8018;

      location / {
            proxy_pass http://back_hmac_md5;
      }
    }

    server {
      listen       8019;

      location / {
            proxy_pass http://back_hmac_sha1;
      }
    }

    server {
      listen       8020;

      location / {
            proxy_pass http://back_domain;
      }
    }

    server {
      listen       8021;

      location / {
            proxy_pass http://back_path;
      }
    }

    server {
      listen       8022;

      location / {
            proxy_pass http://back_expires;
      }
    }

    server {
      listen       8023;

      location / {
            proxy_pass http://back_text_md5;
      }
    }

    server {
      listen       8024;

      location / {
            proxy_pass http://back_text_sha1;
      }
    }

    server {
      listen       8025;

      location / {
            proxy_pass http://back_text_raw;
      }
    }

    server {
      listen       8026;

      location / {
            proxy_pass http://back_no_fallback;
      }
    }

    server {
      listen       8027;

      location / {
            proxy_pass http://back_secure;
      }
    }

    server {
      listen       8028;

      location / {
            proxy_pass http://back_httponly;
      }
    }

    server{
        listen 8008;
        location / {
          return 200 "visit 8008";
        }
    }

    server{
        listen 8009;
        location / {
          return 200 "visit 8009";
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


#my $response = http_get($url);  
diag("Running sticky");
like($t->get_with_port('/', 'localhost', 8010), qr/visit 8008/, 'sticky ip hash');
like($t->get_with_port('/', 'localhost', 8010), qr/visit 8008/, 'sticky ip hash');


like($t->get_with_port('/?c=3', 'localhost', 8011), qr/visit 8008/, 'sticky url');
like($t->get_with_port('/?c=3', 'localhost', 8011), qr/visit 8008/, 'sticky url');

like($t->get_with_port('/?aaa=3', 'localhost', 8012), qr/visit 8008/, 'sticky arg');
like($t->get_with_port('/?aaa=3', 'localhost', 8012), qr/visit 8008/, 'sticky arg');

like($t->get_with_port('/', 'localhost', 8013, "test: 12345"), qr/visit 8008/, 'sticky header');
like($t->get_with_port('/', 'localhost', 8013, "test: 12345"), qr/visit 8008/, 'sticky header');

like($t->get_with_port('/', 'localhost', 8014, "cookie: wisegrid=12345"), qr/visit 8008/, 'sticky header');
like($t->get_with_port('/', 'localhost', 8014, "cookie: wisegrid=12345"), qr/visit 8008/, 'sticky header');

like($t->get_with_port('/', 'localhost', 8015), qr/wisegrid=/, 'sticky default');
like($t->get_with_port('/', 'localhost', 8015), qr/wisegrid=/, 'sticky default');


like($t->get_with_port('/', 'localhost', 8016), qr/wisegrid=/, 'sticky hash_md5');
like($t->get_with_port('/', 'localhost', 8017), qr/wisegrid=/, 'sticky hash_sha1');
like($t->get_with_port('/', 'localhost', 8018), qr/wisegrid=/, 'sticky hmac_md5');
like($t->get_with_port('/', 'localhost', 8019), qr/wisegrid=/, 'sticky hmac_sha1');
like($t->get_with_port('/', 'localhost', 8020), qr/Domain=/, 'sticky domain');
like($t->get_with_port('/', 'localhost', 8021), qr/Path=/, 'sticky path');
like($t->get_with_port('/', 'localhost', 8022), qr/Expires=/, 'sticky expires');
like($t->get_with_port('/', 'localhost', 8023), qr/wisegrid=/, 'sticky text_md5');
like($t->get_with_port('/', 'localhost', 8024), qr/wisegrid=/, 'sticky text_sha1');
like($t->get_with_port('/', 'localhost', 8025), qr/wisegrid=/, 'sticky text_raw');
like($t->get_with_port('/', 'localhost', 8026), qr/wisegrid=/, 'sticky no_fallback');
like($t->get_with_port('/', 'localhost', 8027), qr/Secure/, 'sticky secure');
like($t->get_with_port('/', 'localhost', 8028), qr/HttpOnly/, 'sticky httponly');