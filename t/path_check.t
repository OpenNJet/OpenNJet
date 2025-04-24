#!/usr/bin/perl   #是perl 解释器的路径

# (C) Sergey Kandaurov

# Tests for nginx access module.

# At the moment only the new "unix:" syntax is tested (cf "all").

###############################################################################

use warnings; 

use strict;  
# use File::Slurper 'read_dir';

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;  
# use Data::Dumper;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;


my $t = Test::Nginx->new()->plan(19);
my $njet_module_path = set_njet_module_path(); 
warn "--------------njet_module_path = $njet_module_path";
$t->{_expand_vars} = {
    njet_module_path => $njet_module_path
};

$t->write_file_expand('njet.conf', <<'EOF');

%%TEST_GLOBALS%%
#daemon off;
helper broker %%njet_module_path%%/njt_helper_broker_module.so conf/mqtt.conf;
helper ctrl %%njet_module_path%%/njt_helper_ctrl_module.so conf/njet_ctrl.conf;
helper rsyn %%njet_module_path%%/njt_helper_rsync_module.so conf/rsync.conf;
helper access_data %%njet_module_path%%/njt_helper_access_data_module.so conf/goaccess.conf;

load_module  %%njet_module_path%%/njt_http_dyn_map_module.so;
load_module %%njet_module_path%%/njt_agent_dynlog_module.so;
load_module %%njet_module_path%%/njt_http_location_module.so;
load_module %%njet_module_path%%/njt_http_access_log_zone_module.so;
load_module %%njet_module_path%%/njt_app_sticky_module.so;
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

        server {
                listen 238.255.253.254:5566 udp;
                gossip zone=test:1m heartbeat_timeout=100ms nodeclean_timeout=1s local_ip=192.168.40.136 ctrl_port=8081 sync_port=8874 bridge_port=1887;
        }
}


http {
    include mime.types;
    # log_format aaaa  '$request_time     $upstream_response_time     $upstream_connect_time';
    log_format aaaa '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log logs/access.log aaaa;


    access_log_zone  abc 1m;
    access_log_zone_ignore_ip  127.0.0.1;
    access_log_zone_valid  3;
    access_log_db_path data/access;

     upstream back{
                zone back 10M;
                #server 192.168.40.136:8090;
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


$t->write_file_expand('mqtt.conf', <<'EOF');
log_dest file logs/mosquitto.log
log_type debug
log_type information
log_type error
log_type warning
log_type notice
allow_anonymous true

listener 0 data/mosquitto.sock
persistence true
autosave_on_changes true
autosave_interval 1

listener 1887 192.168.40.136

connection bridge-backup inactive
address 192.168.40.136:1887

topic /dyn/# both 0
topic /ins/# both 0

persistence true
autosave_on_changes true
autosave_interval 1
EOF


$t->write_file_expand('rsync.conf', <<'EOF');
{
    "log_file": "logs/rsync.log",
    "log_level": "debug",
    "watch_dirs": [
        {
            "ignore_files": [
                "1.txt",
                "tmp1/tmp11", 
                "tmp1/*.doc",
                "tmp1/abc.*"
            ],
            "identifier": "dir_name1",
            "prefix": "/root/bug/njet1.0/src",
            "dir": "/root/bug/njet1.0/src/tmp1"
        },
        {
            "identifier": "dir_name2",
            "prefix": "/root/bug/njet1.0/src",
            "dir": "/root/bug/njet1.0/src/tmp2"
        }
    ]
}
EOF


# my $d = $t->testdir();
$t->create_common_configs($t);
$t->custom_run('cus_data', 'cus_log');


sleep 2;

my $testdir = $t->testdir();
my $datadir = "$testdir/cus_data/data";
my $logdir = "$testdir/cus_log/logs";

opendir(my $datadh, $datadir) or die "无法打开目录 $datadir: $!";
my @datafiles = grep { !/^\.\.?$/ } readdir($datadh);
closedir($datadh);

my $alldatafiles = "@datafiles";

#5 case
like($alldatafiles, qr/lock.mdb/, 'lock.mdb ok');
like($alldatafiles, qr/data.mdb/, 'data.mdb ok');
like($alldatafiles, qr/dyn_slab/, 'dyn_slab ok');
# like($alldatafiles, qr/file_upload/, 'file_upload ok');
like($alldatafiles, qr/mosquitto.db/, 'mosquitto.db ok');
like($alldatafiles, qr/mosquitto.sock/, 'mosquitto.sock ok');
# like($alldatafiles, qr/add_location.txt/, 'add_location.txt ok');
# like($alldatafiles, qr/add_ups.txt/, 'add_ups.txt ok');
# like($alldatafiles, qr/map.txt/, 'map.txt ok');
# like($alldatafiles, qr/add_server.txt/, 'add_server.txt');


opendir(my $logdh, $logdir) or die "无法打开目录 $logdir: $!";
my @logfiles = grep { !/^\.\.?$/ } readdir($logdh);
closedir($logdh);

my $alllogfiles = "@logfiles";

#14 case
like($alllogfiles, qr/access.log/, 'access.log');
like($alllogfiles, qr/error_ctrl.log/, 'error_ctrl.log ok');
like($alllogfiles, qr/error.log/, 'error.log ok');
like($alllogfiles, qr/goaccess_debug.log/, 'goaccess_debug.log ok');
like($alllogfiles, qr/helper_iot/, 'helper_iot ok');
like($alllogfiles, qr/master_iot/, 'master_iot ok');
like($alllogfiles, qr/mdb_client_access_data/, 'mdb_client_access_data ok');
like($alllogfiles, qr/mdb_client_broker/, 'mdb_client_broker ok');
like($alllogfiles, qr/mdb_client_ctrl/, 'mdb_client_ctrl ok');
like($alllogfiles, qr/mdb_client_rsyn/, 'mdb_client_rsyn ok');
like($alllogfiles, qr/mosquitto.log/, 'mosquitto.log ok');
like($alllogfiles, qr/rsync.log/, 'rsync.log ok');
like($alllogfiles, qr/sendmsg_/, 'sendmsg_ ok');
like($alllogfiles, qr/work_iot/, 'work_iot ok');



#diag("Running /shm/format/html format");
#like(http_get($url), qr/"server": "127.0.0.1:8008"/, 'peer status html format ok');
