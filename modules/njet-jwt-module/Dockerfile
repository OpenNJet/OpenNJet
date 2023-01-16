FROM nginx:1.19.10-alpine as base

FROM base as builder

ARG JWT_MODULE_PATH=/usr/local/lib/ngx-http-auth-jwt-module
ARG LIBJWT_VERSION=1.12.1

RUN mkdir -p $JWT_MODULE_PATH/src

RUN apk add --no-cache \
  # nginx
  gcc \
  libc-dev \
  make \
  openssl-dev \
  pcre-dev \
  zlib-dev \
  linux-headers \
  curl \
  gnupg \
  libxslt-dev \
  gd-dev \
  # libjwt
  jansson-dev \
  autoconf \
  automake \
  libtool \
  cmake \
  check-dev

# BEGIN libjwt install
RUN mkdir libjwt \
  && curl -sL https://github.com/benmcollins/libjwt/archive/v${LIBJWT_VERSION}.tar.gz \
   | tar -zx -C libjwt/ --strip-components=1 \
  && cd libjwt \
  && autoreconf -i \
  && ./configure \
  && make all \
  && make check \
  && make install

RUN curl -fSL http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -o nginx.tar.gz \
  && mkdir -p /usr/src \
  && tar -zxC /usr/src -f nginx.tar.gz \
  && rm nginx.tar.gz

ADD config $JWT_MODULE_PATH/config
ADD src $JWT_MODULE_PATH/src

RUN cd /usr/src/nginx-${NGINX_VERSION} \
  && ./configure --with-compat --add-dynamic-module=$JWT_MODULE_PATH \
  && make modules

FROM base

ARG LIBJWT=libjwt.so.1.7.0

COPY --from=builder /usr/src/nginx-${NGINX_VERSION}/objs/ngx_http_auth_jwt_module.so /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so
COPY --from=builder /usr/local/lib/${LIBJWT} /lib

RUN apk add --no-cache jansson \
  && sed -i '1iload_module modules/ngx_http_auth_jwt_module.so;' /etc/nginx/nginx.conf \
  && ln -s /lib/${LIBJWT} /lib/libjwt.so.1 \
  && ln -s /lib/${LIBJWT} /lib/libjwt.so
