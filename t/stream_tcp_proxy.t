#!/usr/bin/perl

# (C) Andrey Zelenkov
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Stream tests for tcp_nodelay.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;


my $t = Test::Nginx->new()->has(qw/stream/)->plan(1);
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

cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 

events {
        worker_connections 1024; 
}

stream {
    #%%TEST_GLOBALS_STREAM%%

    proxy_buffer_size 1;

    server {
        listen      127.0.0.1:8001;
        proxy_pass  127.0.0.1:8003;
    }
}


http {
    include mime.types;
log_format aaaa '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log logs/access.log aaaa;


     upstream back{
                zone back 10M;
app_sticky zone=app:4m cookie:route;
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
     listen 127.0.0.1:8083;

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

$t->create_common_configs($t);

$t->run_daemon(\&stream_daemon, port(8003));
$t->run()->waitforsocket('127.0.0.1:' . port(8003));

###############################################################################

my $str = '1234567890' x 10 . 'F';
my $length = length($str);

is(stream('127.0.0.1:' . port(8001))->io($str, length => $length), $str,
	'tcp proxy pass');

###############################################################################
sub stream_daemon {
    my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . port($port),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($server);

	local $SIG{PIPE} = 'IGNORE';

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($server == $fh) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif (stream_handle_client($fh)) {
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub stream_handle_client {
	my ($client) = @_;

	log2c("(new connection $client)");

	$client->sysread(my $buffer, 65536) or return 1;

	log2i("$client $buffer");

	my $close = $buffer =~ /F/;

	log2o("$client $buffer");

	$client->syswrite($buffer);

	return $close;
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||', @_); }


###############################################################################
