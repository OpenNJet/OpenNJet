Name
====

form-input-nginx-module - NGINX module that reads HTTP POST and PUT request body encoded in "application/x-www-form-urlencoded" and parses the arguments into nginx variables.

Table of Contents
=================

* [Name](#name)
* [Description](#description)
* [Installation](#installation)
    * [Building as a dynamic module](#building-as-a-dynamic-module)
* [Usage](#usage)
* [Limitations](#limitations)
* [Compatibility](#compatibility)
* [Copyright & License](#copyright--license)

Description
===========

This is a nginx module that reads HTTP POST and PUT request body encoded
in "application/x-www-form-urlencoded", and parse the arguments in
request body into nginx variables.

This module depends on the ngx_devel_kit (NDK) module.

Installation
============

Grab the nginx source code from [nginx.org](http://nginx.org/), for example,
the version 1.9.15 (see [nginx compatibility](#compatibility)), and then build the source with this module:

```bash
wget 'http://nginx.org/download/nginx-1.9.15.tar.gz'
tar -xzvf nginx-1.9.15.tar.gz
cd nginx-1.9.15/

./configure --add-module=/path/to/ngx_devel_kit \
    --add-module=/path/to/form-input-nginx-module

make -j2
make install
```

Download the latest version of the release tarball of this module from [form-input-nginx-module file list](http://github.com/calio/form-input-nginx-module/tags), and the latest tarball for [ngx_devel_kit](https://github.com/simpl/ngx_devel_kit) from its [file list](https://github.com/simpl/ngx_devel_kit/tags).

Building as a dynamic module
----------------------------

Starting from NGINX 1.9.11, you can also compile this module as a dynamic module, by using the `--add-dynamic-module=PATH` option instead of `--add-module=PATH` on the
`./configure` command line above. And then you can explicitly load the module in your `nginx.conf` via the [load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module)
directive, for example,

```nginx
load_module /path/to/modules/ndk_http_module.so;  # assuming NDK is built as a dynamic module too
load_module /path/to/modules/ngx_http_form_input_module.so;
```

[Back to TOC](#table-of-contents)

Usage
=====

```nginx
set_form_input $variable;
set_form_input $variable argument;

set_form_input_multi $variable;
set_form_input_multi $variable argument;
```

example:

```nginx
#nginx.conf

location /foo {
    # ensure client_max_body_size == client_body_buffer_size
    client_max_body_size 100k;
    client_body_buffer_size 100k;

    set_form_input $data;    # read "data" field into $data
    set_form_input $foo foo; # read "foo" field into $foo
}

location /bar {
    # ensure client_max_body_size == client_body_buffer_size
    client_max_body_size 1m;
    client_body_buffer_size 1m;

    set_form_input_multi $data; # read all "data" field into $data
    set_form_input_multi $foo data; # read all "data" field into $foo

    array_join ' ' $data; # now $data is an string
    array_join ' ' $foo;  # now $foo is an string
}
```

[Back to TOC](#table-of-contents)

Limitations
===========

* ngx_form_input will discard request bodies that are buffered
to disk files. When the client_max_body_size setting is larger than
client_body_buffer_size, request bodies that are larger
than client_body_buffer_size (but no larger than
client_max_body_size) will be buffered to disk files.
So it's important to ensure these two config settings take
the same values to avoid confustion.

[Back to TOC](#table-of-contents)

Compatibility
=============

The following versions of Nginx should work with this module:

* 1.9.x (last tested: 1.9.15)
* 1.8.x
* 1.7.x (last tested: 1.7.4)
* 1.6.x
* 1.5.x (last tested: 1.5.12)
* 1.4.x (last tested: 1.4.6)
* 1.1.x (last tested: 1.1.5)
* 1.0.x (last tested: 1.0.8)
* 0.9.x (last tested: 0.9.4)
* 0.8.x >= 0.8.54

[Back to TOC](#table-of-contents)

Copyright & License
===================

Copyright (c) 2010, 2011, Jiale "calio" Zhi <vipcalio@gmail.com>.

Copyright (c) 2010-2016, Yichun "agentzh" Zhang <agentzh@gmail.com>, CloudFlare Inc.

This module is licensed under the terms of the BSD license.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

