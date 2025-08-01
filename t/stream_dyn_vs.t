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

my $t = Test::Nginx->new()->plan(7);
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

    resolver 127.0.0.1:%%PORT_8981_UDP%% valid=5s;

     server {
     server_name server-90;
     listen 0.0.0.0:90;

       location /merge {
            
                  return 200 "ok\n";
       
      }
      
    }

}
stream {
    %%TEST_GLOBALS_STREAM%%

    # lower the retry timeout after empty reply
    resolver 127.0.0.1:%%PORT_8981_UDP%% valid=1s;
    # retry query shortly after DNS is started
    resolver_timeout 1s;

    log_format test $upstream_addr;
    server {
        listen 0.0.0.0:7082 mesh;
		set $mesh_server_name server-27082;
        return "7082  ok";
    }
    server {
        listen 0.0.0.0:7083 udp;
        return "7083  ok";
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


# my $d = $t->testdir();
$t->create_common_configs($t);
$t->run();
sleep(2);

my $stream_url = '/';  
#my $response = http_get($url);  
diag("Running query default stream vs 1");
my $result1 =$t->get_with_port($stream_url, 'localhost', 7082);

like($result1, qr/7082  ok/, 'default stream vs ok');




my $json_payload_vs = '{
  "type": "add",
  "addr_port": "0.0.0.0:7082",
  "server_name": "server-27082",
  "server_body": "return \"server-27082 ok!\";" 
}';  

my $r;

$r = http(<<EOF);
POST /api/v1/stream_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_vs)]}

$json_payload_vs 

EOF

diag("Running add stream vs 2");
like($r, qr/"code":0,"msg":"success./, 'post vs');
sleep(1);

diag("Running query new stream vs 3");
my $result2 =$t->get_with_port($stream_url, 'localhost', 7082);

like($result2, qr/server-27082 ok!/, 'new stream vs ok');


diag("Running query del new stream vs 4");

my $json_del_vs = '{
  "type": "del",
  "addr_port": "0.0.0.0:7082",
  "server_name": "server-27082"
}'; 

$r = http(<<EOF);
PUT /api/v1/stream_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_del_vs)]}

$json_del_vs 

EOF

like($r, qr/"code":0,"msg":"success./, 'del new vs ok');

sleep(1);
diag("Running query del new stream vs 5");
$result1 =$t->get_with_port($stream_url, 'localhost', 7082);

like($result1, qr/7082  ok/, 'default stream vs ok');



diag("Running query add new stream udp vs 6");
$json_payload_vs = '{
  "type": "add",
  "addr_port": "0.0.0.0:7083 udp",
  "server_name": "server-27083",
  "server_body": "return \"server-27083 ok!\";" 
}';  

$r = http(<<EOF);
POST /api/v1/stream_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_payload_vs)]}

$json_payload_vs 

EOF
like($r, qr/"code":0,"msg":"success./, 'post vs');
sleep(1);


diag("Running query del new stream udp vs 7");

$json_del_vs = '{
  "type": "del",
  "addr_port": "0.0.0.0:7083 udp",
  "server_name": "server-27083"
}'; 

$r = http(<<EOF);
PUT /api/v1/stream_srv HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($json_del_vs)]}

$json_del_vs 

EOF

like($r, qr/"code":0,"msg":"success./, 'del new vs ok');
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
