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


my $t = Test::Nginx->new()->plan(15);
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

load_module %%njet_module_path%%/njt_agent_dynlog_module.so;
load_module %%njet_module_path%%/njt_http_location_module.so; 
load_module %%njet_module_path%%/njt_http_testcookie_access_module.so;

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

    testcookie off;

    #setting cookie name

    server {
        listen 8004;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_domain test.com;
        testcookie_path /;
        testcookie_expires 3d;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }

    server {
        listen 8005;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;

        location / {
            #enable module for specific location
            testcookie on;
            testcookie_refresh_status 201;
            
            index 8082.html;
        }
    }

    server {
        listen 8006;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;

        testcookie_whitelist {
            8.8.8.8/32;
            127.0.0.1/32;
        }

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }

    server {
        listen 8007;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;
        testcookie_refresh_template 'hello world!';

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }


    server {
        listen 8008;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;
        testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

        testcookie_refresh_encrypt_cookie on;
        testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;
        testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }

    server {
        listen 8009;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;
        testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

        testcookie_refresh_encrypt_cookie on;
        testcookie_refresh_encrypt_cookie_key random;
        testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }

    server {
        listen 8010;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;
        testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

        testcookie_refresh_encrypt_cookie on;
        testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;
        testcookie_refresh_encrypt_cookie_iv random;

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }

    server {
        listen 8011;
        server_name test.com;

        testcookie_name tmlake;
        testcookie_secret keepmesecretflagmeblaflagmeblaflagmebla;
        testcookie_session $remote_addr$http_user_agent;
        testcookie_arg tstc;
        testcookie_max_attempts 3;
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
        testcookie_redirect_via_refresh on;
        testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

        testcookie_refresh_encrypt_cookie on;
        testcookie_refresh_encrypt_cookie_key random;
        testcookie_refresh_encrypt_cookie_iv random;

        location / {
            #enable module for specific location
            testcookie on;
            
            index 8082.html;
        }
    }


}
		
EOF

$t->write_html_file('8082.html', <<'EOF');
<!DOCTYPE html>
<html>
<head>
<title>Welcome to njet  8082!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to njet!</h1>
<p>If you see this page, the njet web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://njet.org/">njet.org</a>.<br/>
Commercial support is available at
<a href="http://njet.com/">njet.com</a>.</p>

<p><em>Thank you for using njet.</em></p>
</body>
</html>

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

diag("Running test attemps");
like($t->get_with_port("/", "localhost", 8004), qr/302/, 'testcookie 302 first');
like($t->get_with_port("/?tstc=1", "localhost", 8004), qr/302/, 'testcookie 302 second');
like($t->get_with_port("/?tstc=3", "localhost", 8004), qr/google.com/, 'testcookie 302 fallback');


diag("Running test base");
like($t->get_with_port("/", "localhost", 8004), qr/domain=test.com/, 'testcookie domain');
like($t->get_with_port("/", "localhost", 8004), qr/path=\//, 'testcookie path');
like($t->get_with_port("/", "localhost", 8004), qr/tmlake=/, 'testcookie name');
like($t->get_with_port("/", "localhost", 8004), qr/expires=/, 'testcookie expires');


diag("Running test refresh");
like($t->get_with_port("/", "localhost", 8005), qr/Refresh/, 'testcookie refresh');
like($t->get_with_port("/", "localhost", 8005), qr/Refresh/, 'testcookie refresh code 201');

diag("Running white list");
like($t->get_with_port("/", "localhost", 8006), qr/Welcome to njet/, 'testcookie white list');

diag("Running custom refresh template");
like($t->get_with_port("/", "localhost", 8007), qr/hello world/, 'testcookie custom refresh template');

diag("Running custom refresh template, encrypted variables, static key");
like($t->get_with_port("/", "localhost", 8008), qr/(\w){32} deadbeefdeadbeefdeadbeefdeadbeef deadbeefdeadbeefdeadbeefdeadbeef/, 'testcookie encrypted variables static key');

diag("Running custom refresh template, encrypted variables, random key");
like($t->get_with_port("/", "localhost", 8009), qr/(\w){32} deadbeefdeadbeefdeadbeefdeadbeef (\w){32}$/, 'testcookie encrypted variables random key');

diag("Running custom refresh template, encrypted variables, random iv");
like($t->get_with_port("/", "localhost", 8010), qr/(\w){32} (\w){32} deadbeefdeadbeefdeadbeefdeadbeef$/, 'testcookie encrypted variables random iv');

diag("Running custom refresh template, encrypted variables, random key and iv");
like($t->get_with_port("/", "localhost", 8011), qr/(\w){32} (\w){32} (\w){32}$/, 'testcookie encrypted variables random key and iv');


