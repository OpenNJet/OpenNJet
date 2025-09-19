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
load_module %%njet_module_path%%/njt_http_location_module.so; 
load_module %%njet_module_path%%/njt_stream_dyn_ssl_module.so; 


cluster_name helper;
node_name node1;
worker_processes auto;   
user root;

events {
	worker_connections 1024; 
}


stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen       8000 ssl;
        server_name  dev.test.com;
        ssl_ntls on;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        proxy_pass localhost:8008;
    }
}


http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       8008;

      location / {
        return 200 "=======8008";
      }
    }
}

EOF



$t->write_file_expand('njet_ctrl.conf', <<'EOF');

load_module %%njet_module_path%%/njt_http_sendmsg_module.so; 
load_module %%njet_module_path%%/njt_ctrl_config_api_module.so; 
load_module %%njet_module_path%%/njt_http_upstream_api_module.so; 
load_module %%njet_module_path%%/njt_http_location_api_module.so; 
load_module %%njet_module_path%%/njt_doc_module.so;
load_module %%njet_module_path%%/njt_stream_ssl_api_module.so;

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
		listen 8080; 
    
    
		 location /api {
        dyn_module_api;
    }

    location /doc {
        doc_api;
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


my $url = '/api/v1/stream_ssl';  
my $response = $t->get_with_port($url, 'localhost', 8080);  
diag("Running test get stream config cert");
like($response, qr/localhost.key/, 'get stream config cert');

my $r;

my $rsa_json_payload = '{  
  "listens": [
        "0.0.0.0:8000"
    ],
    "serverNames": [
        "dev.test.com"
    ],
    "type": "add",

    "cert_info": {
        "cert_type": "rsa",
        "certificate": "data:-----BEGIN CERTIFICATE-----\r\nMIIDZjCCAk6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJDTjEQ\r\nMA4GA1UEBwwHQmVpamluZzENMAsGA1UECgwEdGVzdDERMA8GA1UECwwIUGVyc29u\r\nYWwxFTATBgNVBAMMDGRldi50ZXN0LmNvbTAeFw0yNDA5MTgwNzQ2MzBaFw0yNTA5\r\nMTgwNzQ2MzBaMEYxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDAR0ZXN0MREwDwYDVQQL\r\nDAhQZXJzb25hbDEVMBMGA1UEAwwMZGV2LnRlc3QuY29tMIIBIjANBgkqhkiG9w0B\r\nAQEFAAOCAQ8AMIIBCgKCAQEApeLlfW7NnvDR0HAxeDOmmY5vQ+cFxNB6ccUXjdRC\r\nHa9ygn0IGzP/haW1eSZfhWKjKaUaUnfVr/R+Z+uVX8omhQt1Xj3Lt2TEmLWWSYyf\r\nPjuDbjxBlfxxnvnT7ivLi8UFW6r4oTNW1zuJEa1XzZpcRyPoR6IofYuCvb20vgj9\r\neRw6nNC8giEeNPZFfcMvMMwgQCrL47rhvaVlamhLqEnOjmHS+s3HgNhJ2vKqaYiQ\r\nN1y0/4J/OYdJj3NZRdMypguLEqAzDTyDGwori1bvy13am8s9PIEHfacDHqIHbj+e\r\n1cfgyB0Ms7RMi6E/IIoqqCd5TSfiXivtClvaoBzpcEy4jwIDAQABo00wSzAJBgNV\r\nHRMEAjAAMB0GA1UdDgQWBBTFAPpPjPjTyBiAgVbh2L6k0/y0WjAfBgNVHSMEGDAW\r\ngBRy6MYpgHugI8hGQ/5kI/HflEtqQzANBgkqhkiG9w0BAQsFAAOCAQEAInXiELxx\r\nQZkV7jN2+c3uJJ9WGc9BCwDkRylnb9mOEw91olqT3U7pCkN87CHIPt/lJsGH8WYK\r\nO4ob6j1MTZN903P7F3yg4Aztv8QNmP81YKQwzRkGVj6QX6saTkIZhu7RMLLyMHbe\r\nw7ZTUKe/V49PqgVHdnQG9kUIhrd+ntgweN3lRLHBPxyexloL235DXdH28xYpzqmB\r\nl7KvV/mKJ5oXEfByziLJRhGPlWG0gutjbSN8mbH7LII+OlkfolY6ltVxjHNXPOL1\r\nI/vWwVH4GXR+rCZe2U5DPyK2iyyicVvKOvc2RRRdUdx/fDLEa3FIVhKRIBHh/W8W\r\nL7IKTYB+CP08Gg==\r\n-----END CERTIFICATE-----\r\n",
        "certificateKey": "data:-----BEGIN PRIVATE KEY-----\r\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCl4uV9bs2e8NHQ\r\ncDF4M6aZjm9D5wXE0HpxxReN1EIdr3KCfQgbM/+FpbV5Jl+FYqMppRpSd9Wv9H5n\r\n65VfyiaFC3VePcu3ZMSYtZZJjJ8+O4NuPEGV/HGe+dPuK8uLxQVbqvihM1bXO4kR\r\nrVfNmlxHI+hHoih9i4K9vbS+CP15HDqc0LyCIR409kV9wy8wzCBAKsvjuuG9pWVq\r\naEuoSc6OYdL6zceA2Ena8qppiJA3XLT/gn85h0mPc1lF0zKmC4sSoDMNPIMbCiuL\r\nVu/LXdqbyz08gQd9pwMeogduP57Vx+DIHQyztEyLoT8giiqoJ3lNJ+JeK+0KW9qg\r\nHOlwTLiPAgMBAAECggEAInwgqQq3xCrb8zDfl9Vk9NcfWkZUdK3CRpRqaRmPBQzM\r\nCURkwwL0Q5xHNYA8q0XuFWI1Lp+q1IFHJeNbkiY8C7xuEcFW8DEKjZRyQafyEsXc\r\ndLYiDEQGer4EyKZiEhRLINtSBHDfxK6juAEJF7zXIhLc3sdfE3pFG5ysTjUgPGTE\r\nD1uSVHwW3gcVgI8Wvn3Gns3CVr6moEPdidRk33XFD4Y2Snr5Sp78zKVVD0kQd8g3\r\nqdDXC3RZdjo5tzuC3MKnClDjKLiM/ftdhd+MbEWOX31CJNzNVjfhwb0fmiLqAysT\r\nIQWevOhjo47CbnAcXDbU3MhC7zc8aR/cWJePoJ2qwQKBgQDBSFlAJ77FvubhiA7I\r\nB+YOAOaSI+kSjiGS1j7Sz8qv038S3B5bygp4r16LmwsqtjP3Yq1GLigdHy+nd84F\r\nwYGTImxLkOTwE5YP4Aq6ei3zicWEE6lgHgetFQiwFTHjWbidibapEMTpKwgIh/NO\r\nwHGVcV5V2EB76BfA1RctA7H+VQKBgQDbtsjt2IjqYo5/U0UG2SSCc8wYl/cjiYL2\r\nP6TpXXuT4eiA+KE4MtCvIQQUMn1msPLve00qFO282bjMFXnJX7M8ZGdctRguVx41\r\nM2UeZXGLR1GbDhrOjRJ743AgpOtheij/+O/J9XqTtQjw5huxIdNVSNNTQojDDZdt\r\nXTaWPSc3UwKBgA/UE/MMDjR1gMThdoxtESr+aeN362Nonlk/EGAFQk0J3fM2cYoE\r\nzry5Z9248b4qs7DDtPr1VrWj0yw8xHN2OF1LSWEa2ZTLldNw/o/s54x1MOazEYDc\r\nlLZY7aA17CL5OwQzvfC0fdu2eW7xazx8yBB7+0S+c/FxvVg+WyqFjfMNAoGAcJIk\r\nPIiXDc/VRrM5SJr0s8n0ph0mSJTp/pT5P3/gExLJ91pr78lJVpFJ77c2vOiob77y\r\n+D6k1/+NSTMvpNddk/G1a7B1ZTjJh2R/yKUdGck+rHz7ixyIfeU3y+Hzn4vhedTn\r\ntsgJN6innhWn1oeIKcgYTi5mt9k83pHFqBBJCXUCgYEAjS17tpgYHSckH8bkeDk7\r\nXFR/WUgNux4AG1cFFxp3MNibZWNS/OVnQ/V4QMjx+Hv2yG5+/JE+Z519uD0hVkkG\r\n+4tsHlAWEHaSrAxORB7EAtNNtqe1MzO4R3fSFm61Se40lsowdFMtnpbOjPddw9FW\r\neNJs7REZLwf1VSetjHGUNI0=\r\n-----END PRIVATE KEY-----\r\n"
    }
}';


my $ecc_json_payload = '{  
  "listens": [
        "0.0.0.0:8000"
    ],
    "serverNames": [
        "dev.test.com"
    ],
    "type": "add",

    "cert_info": {
        "cert_type": "ecc",
        "certificate": "data:-----BEGIN CERTIFICATE-----\r\nMIICBzCCAY6gAwIBAgIBAjAKBggqhkjOPQQDAjBGMQswCQYDVQQGEwJDTjENMAsG\r\nA1UECgwEdGVzdDERMA8GA1UECwwIUGVyc29uYWwxFTATBgNVBAMMDGRldi50ZXN0\r\nLmNvbTAeFw0yNDA5MTgwNjA1MzBaFw0zNDA5MTYwNjA1MzBaMEYxCzAJBgNVBAYT\r\nAkNOMQ0wCwYDVQQKDAR0ZXN0MREwDwYDVQQLDAhQZXJzb25hbDEVMBMGA1UEAwwM\r\nZGV2LnRlc3QuY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZClW+Krt2GK0Crn2\r\nM5kxAczH/pyfer6SFgcHQSU8HBfwtWWsPpvX54WDstPKER6WOYuZ70IprpXnml6H\r\naGgo8weYRUuMNF54MINe1QyRmB8PzC9cuCLHZOndWTby9VFso1AwTjAdBgNVHQ4E\r\nFgQUg2+baoVoMkCuziTB2Lvgx9CxXv8wHwYDVR0jBBgwFoAUg2+baoVoMkCuziTB\r\n2Lvgx9CxXv8wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNnADBkAjAFLPYfQmr5\r\no0AsDcJJmIPzBOrA973oIhOQ29qIARe7kvjR54fIcNatLaO7WHeB3iMCMGWQq4E3\r\nHki8+rzZBrm4MEkwl/nvF/jUCOus/6Fwf60aRPL2aKxAoXiU/wXKi/HCew==\r\n-----END CERTIFICATE-----\r\n",
        "certificateKey": "data:-----BEGIN EC PARAMETERS-----\r\nBgUrgQQAIg==\r\n-----END EC PARAMETERS-----\r\n-----BEGIN EC PRIVATE KEY-----\r\nMIGkAgEBBDDOJ62NL3mSPwy4ryTVitxlr0wat+5a0i7uyHn4hRMY0OlZpwsxOxIu\r\nMw3n2mHoN+WgBwYFK4EEACKhZANiAARkKVb4qu3YYrQKufYzmTEBzMf+nJ96vpIW\r\nBwdBJTwcF/C1Zaw+m9fnhYOy08oRHpY5i5nvQimuleeaXodoaCjzB5hFS4w0Xngw\r\ng17VDJGYHw/ML1y4Isdk6d1ZNvL1UWw=\r\n-----END EC PRIVATE KEY-----\r\n"
    }
}';

my $ntls_json_payload = '{  
  "listens": [
        "0.0.0.0:8000"
    ],
    "serverNames": [
        "dev.test.com"
    ],
    "type": "add",

    "cert_info": {
        "cert_type": "ntls",
        "certificate": "data:-----BEGIN CERTIFICATE-----\r\nMIIB3zCCAYWgAwIBAgIBATAKBggqgRzPVQGDdTBLMQswCQYDVQQGEwJBQTELMAkG\r\nA1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEVMBMGA1UEAwwMZGV2\r\nLnRlc3QuY29tMB4XDTI0MDkyMzAyMDcxN1oXDTM0MDkyMTAyMDcxN1owSzELMAkG\r\nA1UEBhMCQUExCzAJBgNVBAgMAkJCMQswCQYDVQQKDAJDQzELMAkGA1UECwwCREQx\r\nFTATBgNVBAMMDGRldi50ZXN0LmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA\r\nBKbuJ+paAmrrYkSMZfVf26U3z2WRsx9ypA1IqvOMmdRf/rmuIeIXAtq+k1Y6i9lN\r\nJUlh2+JQI3eqBr17pOXKmCyjWjBYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgbAMB0G\r\nA1UdDgQWBBRbz5pK7DIv4dk+BxrQBEqKjyMXoTAfBgNVHSMEGDAWgBRs8E9SbP7h\r\nYXIhvYjfWslWaNJT6TAKBggqgRzPVQGDdQNIADBFAiEAqudnZOIoTSGIKcidhNAo\r\nbORmYJf6t9L7yJ7IqXnTgpACIF8ScmcmXFJhemvRVWcgjD327MRclFvtF1zD+cD7\r\ncJk5\r\n-----END CERTIFICATE-----\r\n",
        "certificateKey": "data:-----BEGIN PRIVATE KEY-----\r\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg1ev1Np2CFUoHbxE2\r\nnGsXyxfKezmYId/FlKtospIq1KChRANCAASm7ifqWgJq62JEjGX1X9ulN89lkbMf\r\ncqQNSKrzjJnUX/65riHiFwLavpNWOovZTSVJYdviUCN3qga9e6Tlypgs\r\n-----END PRIVATE KEY-----\r\n",
        "certificateEnc": "data:-----BEGIN CERTIFICATE-----\r\nMIIB4DCCAYWgAwIBAgIBAjAKBggqgRzPVQGDdTBLMQswCQYDVQQGEwJBQTELMAkG\r\nA1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEVMBMGA1UEAwwMZGV2\r\nLnRlc3QuY29tMB4XDTI0MDkyMzAyMDcxN1oXDTM0MDkyMTAyMDcxN1owSzELMAkG\r\nA1UEBhMCQUExCzAJBgNVBAgMAkJCMQswCQYDVQQKDAJDQzELMAkGA1UECwwCREQx\r\nFTATBgNVBAMMDGRldi50ZXN0LmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA\r\nBBW4tCnAleXG+s3DRcRJUl94DW3+WpsGIxW+6jZKStQ2w6uVs0Zfpz0fvRZA7xDQ\r\nsG73PwDde68qtq3dZu+ulnGjWjBYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgM4MB0G\r\nA1UdDgQWBBSvkXE4GSFVR4Is8Fw0BKo5fqIkGzAfBgNVHSMEGDAWgBRs8E9SbP7h\r\nYXIhvYjfWslWaNJT6TAKBggqgRzPVQGDdQNJADBGAiEAkXhKWZEYWuB2Aq0XZAYZ\r\nfHOXggK7Gplf+lTPzF2q1ugCIQDUPHl1qdjXJnuY/mv4POLlYr3m8cm05WugJPKL\r\nPXr2Sg==\r\n-----END CERTIFICATE-----\r\n",
        "certificateKeyEnc": "data:-----BEGIN PRIVATE KEY-----\r\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgHE+sUHvFuO9F3Eeg\r\ny1hbTADkrm4vA+Nz5fat8H+/dg6hRANCAAQVuLQpwJXlxvrNw0XESVJfeA1t/lqb\r\nBiMVvuo2SkrUNsOrlbNGX6c9H70WQO8Q0LBu9z8A3XuvKrat3WbvrpZx\r\n-----END PRIVATE KEY-----\r\n"
    }
}';



$response = http(<<EOF);
PUT /api/v1/config/stream_ssl HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($rsa_json_payload)]}

$rsa_json_payload 

EOF

diag("Running test put stream rsa cert");
like($response, qr/"code":0,"msg":"success./, 'put rsa stream cert');



$response = http(<<EOF);
PUT /api/v1/config/stream_ssl HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($ecc_json_payload)]}

$ecc_json_payload 

EOF

diag("Running test put stream ecc cert");
like($response, qr/"code":0,"msg":"success./, 'put ecc stream cert');


$response = http(<<EOF);
PUT /api/v1/config/stream_ssl HTTP/1.1
Host: localhost
Connection: close
Content-Length: @{[length($ntls_json_payload)]}

$ntls_json_payload

EOF

diag("Running test put stream ntls cert");
like($response, qr/"code":0,"msg":"success./, 'put ntls stream cert');



$response =$t->get_with_port($url, 'localhost', 8080);
like($response, qr/ntls/, 'get stream ntls cert');
like($response, qr/MIICBzCCAY6gAw/, 'get stream ecc cert');
like($response, qr/MIIDZjCCAk6gAwI/, 'get stream rsa cert');
