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

my $t = Test::Nginx->new()->plan(4);

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
load_module %%njet_module_path%%/njt_http_ssl_renegotiate_module.so;

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

    add_header X-Verify x$ssl_client_verify:${ssl_client_cert}x;
 
    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    map $request_uri $reneg {
          default 0;
           ~/securearea/?.*   1;
    }

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        ssl_client_certificate 1.example.com.crt;
        ssl_verify_depth 1;
        ssl_verify_client optional;

        ssl_renegotiate $reneg;
        ssl_reneg_client_certificate 1.example.com.crt;
        ssl_reneg_verify_depth 1;

        location /securearea {
            return 200 "body securearea";    
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  localhost;

        ssl_client_certificate 2.example.com.crt;
        ssl_verify_depth 1;
        ssl_verify_client optional;

        set $ssl_renegotiate 1;
        ssl_reneg_client_certificate 2.example.com.crt;
        ssl_reneg_verify_depth 1;

        location /securearea {
            return 200 "body securearea";    
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
		listen 127.0.0.1:8083; 
    
    
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

foreach my $name ('localhost', '1.example.com', '2.example.com','3.example.com') {
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
get('/', 8080, $ctx );
like(get('/securearea', 8080,  $ctx), qr/NONE:x/m, 'session renegotiate');

$ctx = get_ssl_context();
get('/', 8080, $ctx, '1.example.com');
like(get('/securearea', 8080,  $ctx,'1.example.com'), qr/^body securearea$/m, 'session renegotiate');

$ctx = get_ssl_context();
get('/', 8081, $ctx);
like(get('/securearea', 8081,  $ctx), qr/NONE:x/m, 'session renegotiate');

$ctx = get_ssl_context();
get('/', 8081, $ctx, '2.example.com');
like(get('/securearea', 8081,  $ctx,'2.example.com'), qr/^body securearea$/m, 'session renegotiate');

###############################################################################

sub get {
  my ($uri, $port, $ctx, $cert) = @_;
  my $s = get_ssl_socket($port, $cert, $ctx) or return;
  http_get($uri, socket => $s);
}

sub get_ssl_context {
  return IO::Socket::SSL::SSL_Context->new(
    SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
    SSL_session_cache_size => 100
  );
}


sub get_ssl_socket {
  my ($port, $cert, $ctx) = @_;
  my ($s);

  eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    local $SIG{PIPE} = sub { die "sigpipe\n" };
    alarm(8);
    if ($cert) {
      $s = IO::Socket::SSL->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1',
        PeerPort => port($port),
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        SSL_cert_file => "$d/conf/$cert.crt",
        SSL_key_file => "$d/conf/$cert.key",
        SSL_reuse_ctx => $ctx,
        SSL_error_trap => sub { die $_[1] },
      ); 
    } else  {
      $s = IO::Socket::SSL->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1',
        PeerPort => port($port),
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        SSL_reuse_ctx => $ctx,
        SSL_error_trap => sub { die $_[1] },
      );
    }

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
