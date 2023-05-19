[github-license-url]: /blob/master/LICENSE
[docker-url]: https://hub.docker.com/r/maxxt/nginx-jwt-module/

# Nginx jwt auth module
[![Build Status](https://img.shields.io/github/license/maxx-t/nginx-jwt-module.svg)][github-license-url]
[![Build Status](https://img.shields.io/docker/build/maxxt/nginx-jwt-module.svg)][docker-url]
[![Docker pulls](https://img.shields.io/docker/pulls/maxxt/nginx-jwt-module.svg)][docker-url]

This is an NGINX module to check for a valid JWT.

Inspired by [TeslaGov](https://github.com/TeslaGov/ngx-http-auth-jwt-module), [ch1bo](https://github.com/ch1bo/nginx-jwt) and [tizpuppi](https://github.com/tizpuppi/ngx_http_auth_jwt_module), this module intend to be as light as possible and to remain simple.
 - Docker image based on the [official nginx Dockerfile](https://github.com/nginxinc/docker-nginx) (alpine).
 - Light image (~16MB).

## Module:

### Example Configuration:
```nginx
server {
    auth_jwt_key "0123456789abcdef" hex; # Your key as hex string
    auth_jwt     off;

    location /secured-by-cookie/ {
        auth_jwt $cookie_MyCookieName;
    }

    location /secured-by-auth-header/ {
        auth_jwt on;
    }

    location /secured-by-auth-header-too/ {
        auth_jwt_key "another-secret"; # Your key as utf8 string
        auth_jwt on;
    }

    location /secured-by-rsa-key/ {
        auth_jwt_key /etc/keys/rsa-public.pem file; # Your key from a PEM file
        auth_jwt on;
    }

    location /not-secure/ {}
}
```

> Note: don't forget to [load](http://nginx.org/en/docs/ngx_core_module.html#load_module) the module in the main context: <br>`load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;`

### Directives:

    Syntax:	 auth_jwt $variable | on | off;
    Default: auth_jwt off;
    Context: http, server, location

Enables validation of JWT.<hr>

    Syntax:	 auth_jwt_key value [encoding];
    Default: ——
    Context: http, server, location

Specifies the key for validating JWT signature (must be hexadecimal).<br>
The *encoding* otpion may be `hex | utf8 | base64 | file` (default is `utf8`).<br>
The `file` option requires the *value* to be a valid file path (pointing to a PEM encoded key).

<hr>

    Syntax:	 auth_jwt_alg any | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512;
    Default: auth_jwt_alg any;
    Context: http, server, location

Specifies which algorithm the server expects to receive in the JWT.

### Build:
This module is built inside a docker container, from the [nginx](https://hub.docker.com/_/nginx/)-alpine image.

```bash
./build.sh # Will create a "jwt-nginx" (Dockerfile)
```

### Test:
#### Default usage:
```bash
./test.sh # Will create a "jwt-nginx-test" image (from test-image/Dockerfile) based on the "jwt-nginx" one.
```
#### Set image name:
```bash
./test.sh your-image-to-test
```
example:
```bash
./test.sh jwt-nginx-s1 # tests the development image
```
#### Use current container:
```bash
./test.sh --current my-container
```
example:
```bash
# In a first terminal:
docker run --rm --name my-test-container -p 8000:8000 jwt-nginx-test

# In a second one:
./test.sh --current my-test-container
```
