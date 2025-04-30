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
load_module %%njet_module_path%%/njt_app_sticky_module.so;
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


http {
    include mime.types;
    # log_format aaaa  '$request_time     $upstream_response_time     $upstream_connect_time';
    log_format aaaa '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
    access_log logs/access.log aaaa;

    resolver 127.0.0.1:%%PORT_8981_UDP%% valid=5s;

     server {
     server_name server-90;
     listen 0.0.0.0:90;

       location /merge {
            
                  return 200 "ok\n";
       
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
$t->run();

sleep 1;
my $json_payload_vs = '{
  "type": "add",
  "addr_port": "0.0.0.0:90",
  "server_name": "server-901",
  "server_body": "return 200 server-901;" 
}';  

my $r;

$r = http(<<EOF);
POST /api/v1/dyn_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_vs)]}

$json_payload_vs 

EOF

diag("Running add vs 1");
like($r, qr/"code":0,"msg":"success./, 'post vs');


my $json_payload_loc = '{
     "type": "add",
      "addr_port": "0.0.0.0:90",
      "server_name": "server-901",
       "locations": [{
                "location_rule": "",
                "location_name": "/new_location",
                "location_body": "return 200 ok"
        }]
}';

my $json_payload_del_loc = '{
     "type": "del",
      "addr_port": "0.0.0.0:90",
      "server_name": "server-901",
       "location_name": "/new_location"
}';

my $json_payload_header = '{
    "servers": [
     {
      "listens": [
        "0.0.0.0:90"
      ],
      "serverNames": [
        "server-90"
      ],
      "locations": [
        {
          "location": "/merge"
        }
      ]
    },
    {
      "listens": [
        "0.0.0.0:90"
      ],
      "serverNames": [
        "server-901"
      ],
      "locations": [
        {
          "location": "/new_location",
          "headers": [
            {
              "key": "test",
              "value": "test123",
              "always": false
            }
          ]
        }
      ]
    }
  ]
}'; 

my $r_server;

$r_server = http(<<EOF);
POST /api/v1/dyn_loc HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_loc)]}

$json_payload_loc 

EOF

diag("Running add loc 2");
like($r_server, qr/"code":0,"msg":"success./, 'add loc ok');



sleep 2;
my $json_url = '/api/v1/config/http_dyn_header';  
#my $response = http_get($url);  
diag("Running query http_dyn_header /new_location 3");
my $response2 =$t->get_with_port($json_url, 'localhost', 8080);

like($response2, qr/new_location/, 'create /new_location ok');


#post header
my $r_header;

$r_header = http(<<EOF);
PUT /api/v1/config/http_dyn_header HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_header)]}

$json_payload_header 

EOF

diag("Running put header 4");
like($r_header, qr/"code":0,"msg":"success./, 'put header ok');


diag("Running get header value 5");
my $response3 =$t->get_with_port($json_url, 'localhost', 8080);

like($response3, qr/test123/, 'get header value ok');

diag("Running del location 6");
# del location
my $r_del_loc;
$r_del_loc = http(<<EOF);
PUT /api/v1/dyn_loc HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_del_loc)]}

$json_payload_del_loc 

EOF
like($r_del_loc, qr/"code":0,"msg":"success./, 'del location ok');


diag("Running renew  add location 7");
$r_server = http(<<EOF);
POST /api/v1/dyn_loc HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_loc)]}

$json_payload_loc 

EOF
like($r_server, qr/"code":0,"msg":"success./, 'renew add location ok');


$t->reload();
sleep 3;


diag("Running reload get header value 8");
my $response4 =$t->get_with_port($json_url, 'localhost', 8080);
diag($response4);
if ($response4 =~ m/test123/) {
    like($response4, qr/yy123/, 'reload get header value ok')
} else {
    like($response4, qr/merge/, 'reload get header value ok')
}



###############################################################################

sub reply_handler {
        my ($recv_data, $port) = @_;

        my (@name, @rdata);
        
        use constant NOERROR    => 0;
        use constant A          => 1;
        use constant IN         => 1;

        # default values

        my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);

        # decode name
        #warn "--------------count = $count";
        my ($len, $offset) = (undef, 12);
        while (1) {
                $len = unpack("\@$offset C", $recv_data);
                last if $len == 0;
                $offset++;
                push @name, unpack("\@$offset A$len", $recv_data);
                $offset += $len;
        }

        $offset -= 1;
        my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);

        my $name = join('.', @name);
        if ($name eq 'a.example.com' && $type == A) {
                push @rdata, rd_addr($ttl, '127.0.0.1');

        } elsif ($name =~ qr/test.muti.com/ && $type == A && ($count == 1 || $count == 2)) {
                push @rdata, rd_addr($ttl, '127.0.0.2');
        }  elsif ($name =~ qr/test.muti.com/ && $type == A && ($count == 3 || $count == 4) ) {
                push @rdata, rd_addr($ttl, '127.0.0.2');
                push @rdata, rd_addr($ttl, '127.0.0.3');
        } elsif ($name =~ qr/test.muti.com/ && $type == A && $count > 4 ) {
                push @rdata, rd_addr($ttl, '127.0.0.4');
        } 
        $count++;
        $len = @name;
        pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
                0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
        my ($ttl, $addr) = @_;

        my $code = 'split(/\./, $addr)';

        return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

        pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub dns_daemon {
        my ($port, $t) = @_;

        my ($data, $recv_data);
        my $socket = IO::Socket::INET->new(
                LocalAddr    => '127.0.0.1',
                LocalPort    => $port,
                Proto        => 'udp',
        )
                or die "Can't create listening socket: $!\n";

        local $SIG{PIPE} = 'IGNORE';

        # signal we are ready

        open my $fh, '>', $t->testdir() . '/' . $port;
        close $fh;

        while (1) {
                $socket->recv($recv_data, 65536);
                $data = reply_handler($recv_data, $port);
                $socket->send($data);
        }
}

###############################################################################
