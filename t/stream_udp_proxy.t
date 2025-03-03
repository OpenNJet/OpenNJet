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
use Test::Nginx::Stream qw/ dgram /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;


my $t = Test::Nginx->new()->has(qw/stream udp/)->plan(1);

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
load_module %%njet_module_path%%/njt_range_module.so;


cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 

events {
        worker_connections 1024; 
}


range iptables_path=/usr/sbin/iptables;
range ip6tables_path=/usr/sbin/ip6tables;
range type=udp src_ports=9001 dst_port=9002;

stream {
    %%TEST_GLOBALS_STREAM%%

    proxy_timeout        1s;

    server {
        listen           127.0.0.1:%%PORT_9002_UDP%% udp mesh;
        proxy_pass       127.0.0.1:%%PORT_9003_UDP%%;
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

my $d = $t->testdir();

$t->run();

$t->run_daemon(\&udp_daemon, port(9003), $t);

$t->waitforfile($t->testdir . '/' . port(9003));

###############################################################################

my $s = dgram('127.0.0.1:' . port(9002));
is($s->io('2', read => 2), '12', 'proxy responses 2');

# is($s->io('1', read => 1, read_timeout => 0.5), '', 'proxy responses 0');

# $s = dgram('127.0.0.1:' . port(8982));
# is($s->io('1'), '1', 'proxy responses 1');

# $s = dgram('127.0.0.1:' . port(9001));
# is($s->io('2', read => 2), '12', 'proxy responses 2');

# $s = dgram('127.0.0.1:' . port(8983));
# is($s->io('3', read => 3), '123', 'proxy responses default');

# zero-length payload

# $s = dgram('127.0.0.1:' . port(8982));
# $s->write('');
# is($s->read(), 'zero', 'upstream read zero bytes');
# is($s->read(), '', 'upstream sent zero bytes');

# $s->write('');
# is($s->read(), 'zero', 'upstream read zero bytes again');
# is($s->read(), '', 'upstream sent zero bytes again');


###############################################################################
sub udp_daemon {
        my ($port, $t) = @_;

        my $server = IO::Socket::INET->new(
                Proto => 'udp',
                LocalAddr => '127.0.0.1:' . port($port),
                Reuse => 1,
        )
                or die "Can't create listening socket: $!\n";

	# signal we are ready

        open my $fh, '>', $t->testdir() . '/' . port($port);
        close $fh;

        while (1) {
                $server->recv(my $buffer, 65536);

                if (length($buffer) > 0) {
                        $server->send($_) for (1 .. $buffer);

                } else {
                        $server->send('zero');
                        select undef, undef, undef, 0.2;
                        $server->send('');
                }
        }
}


###############################################################################
