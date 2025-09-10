#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Andrey Zelenkov
# (C) Nginx, Inc.
# (C) TMLake, Inc.

# Tests for http ssl module.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()->plan(5);
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
load_module %%njet_module_path%%/njt_http_ssl_ticket_module.so;

shared_slab_pool_size  100m;
cluster_name helper;
node_name node1;
worker_processes auto;   
user root; 

events {
	worker_connections 1024; 
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;
    ssl_session_tickets on;

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;

        location /ticket {
            return 200 "body $ssl_session_ticket";
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;
        close_noticket_connection on;

        location /ticket {
            return 200 "body $ssl_session_ticket";
        }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;
        close_noticket_connection off;

        location /ticket {
            return 200 "body $ssl_session_ticket";
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


$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF


my $d = $t->testdir();

foreach my $name ('localhost') {
  system('openssl req -x509 -new '
    . "-config $d/conf/openssl.conf -subj /CN=$name/ "
    . "-out $d/conf/$name.crt -keyout $d/conf/$name.key "
    . ">>$d/openssl.out 2>&1") == 0
    or die "Can't create certificate for $name: $!\n";
}

$t->create_common_configs($t);
$t->run();


###############################################################################

my $ctx;
$ctx = get_ssl_context();

like(get('/ticket', 8080, $ctx), qr/^body d41d8cd98f00b204e9800998ecf8427e$/m, 'session ticket on not close');

like(get('/ticket', 8081, $ctx), qr/^$/m, 'session ticket on closeing');
like(get('/ticket', 8081, $ctx), qr/^body \w{32}$/m, 'session ticket reconnect');

like(get('/ticket', 8082, $ctx), qr/^body d41d8cd98f00b204e9800998ecf8427e$/m, 'session ticket not close');
like(get('/ticket', 8082, $ctx), qr/^body \w{32}$/m, 'session ticket reconnect');

###############################################################################

sub get {
  my ($uri, $port, $ctx) = @_;
  my $s = get_ssl_socket($port, $ctx) or return;
  http_get($uri, socket => $s);
}

sub get_ssl_context {
  return IO::Socket::SSL::SSL_Context->new(
    SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
    SSL_session_cache_size => 100
  );
}

sub get_ssl_socket {
  my ($port, $ctx, %extra) = @_;
  my $s;

  eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    local $SIG{PIPE} = sub { die "sigpipe\n" };
    alarm(8);
    $s = IO::Socket::SSL->new(
      Proto => 'tcp',
      PeerAddr => '127.0.0.1',
      PeerPort => port($port),
      SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
      SSL_reuse_ctx => $ctx,
      SSL_error_trap => sub { die $_[1] },
      %extra
    );
    alarm(0);
  };
  alarm(0);

  if ($@) {
    log_in("died: $@");
    return undef;
  }

  return $s;
}

###############################################################################
