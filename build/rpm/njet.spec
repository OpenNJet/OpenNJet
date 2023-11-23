Name:     njet 
Version:  1.2.3 
Release:  1%{?dist} 

Summary:  OpenNJet Application Engine
License:  MulanPSL-2.0  
URL:      https://gitee.com/njet-rd/njet    

#SOURCE0:  %{name}-%{version}.tar.gz
SOURCE0:  njet_main.tar

Requires(pre): shadow-utils
BuildRequires: systemd make gcc  gcc-c++ vim-common m4 autoconf automake cmake3 zlib-devel openssl-devel pcre-devel libtool libtool-ltdl pkgconfig

%description
OpenNJet 应用引擎是基于 NGINX 的面向互联网和云原生应用提供的运行时组态服务程序，作为底层引擎，OpenNJet 实现了NGINX 云原生功能增强、安全加固和代码重构，利用动态加载机制可以实现不同的产品形态，如Web服务器、流媒体服务器、负载均衡、代理(Proxy)、应用中间件、API网关、消息队列等产品形态等等。

%prep
%setup -q -c -n %{name}-%{version}

%build
mv njet_main njet
cd njet && sed -i 's/--strict-warnings//g' ./build_cc.sh && ./build_cc.sh conf $CI_COMMIT_SHA && make -j `nproc`
if [ -d scripts ]; then
  for i in `find ./scripts -type f`; do
    LUA_PATH="`pwd`/luajit/src/?.lua;;" luajit/src/luajit -bg $i $i 
  done
fi

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/local/njet/{logs,data,modules,lib,sbin,lualib/lib,lualib/clib}
cp -a njet/build/rpm/njet.conf.files/* %{buildroot}
cp -a njet/objs/njet %{buildroot}/usr/local/njet/sbin/
cp -a njet/objs/*.so %{buildroot}/usr/local/njet/modules/
cp -a njet/lualib/lib/* %{buildroot}/usr/local/njet/lualib/lib/
cp -a njet/luajit/src/libluajit.so* %{buildroot}/usr/local/njet/lib/libluajit-5.1.so.2.1.0
if [ -d njet/scripts ]; then
  cp -a njet/scripts/* %{buildroot}/usr/local/njet/modules/
fi
ln -sf libluajit-5.1.so.2.1.0 %{buildroot}/usr/local/njet/lib/libluajit-5.1.so.2
ln -sf libluajit-5.1.so.2.1.0 %{buildroot}/usr/local/njet/lib/libluajit-5.1.so
cd njet/auto/lib/luapkg; DESTDIR=%{buildroot} PREFIX=/usr/local CDIR_linux=njet/lualib/clib LDIR_linux=njet/lualib/lib LUA_CMODULE_DIR=${PREFIX}/${CDIR_linux} LUA_MODULE_DIR=${PREFIX}/${LDIR_linux} make install; cd -
cp -a njet/auto/lib/keepalived/keepalived/emb/.libs/libha_emb.so* %{buildroot}/usr/local/njet/lib 

%pre
if [ "$1" -eq 1 ]; then
   if ! getent group njet >/dev/null 2>&1; then
     /usr/sbin/groupadd njet
   fi
   if ! getent passwd njet >/dev/null 2>&1; then
     /usr/sbin/useradd njet -g njet -M -s /sbin/nologin
   fi
fi

%post

grep -q /usr/local/lib /etc/ld.so.conf

if [ $? != 0 ] ; then
  echo "/usr/local/lib" >> /etc/ld.so.conf
fi

ldconfig

systemctl daemon-reload
systemctl enable njet.service

/usr/sbin/setcap cap_dac_override,cap_dac_read_search,cap_net_bind_service,cap_net_admin,cap_net_raw=eip /usr/local/njet/sbin/njet

%preun
systemctl stop njet.service >/dev/null 2>&1
systemctl disable njet.service
systemctl daemon-reload

%postun
if [ "$1" -eq 0 ]; then
   rm -rf /usr/local/njet/
fi

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/etc/systemd/system/njet.service.d/filelimit.conf
/etc/ld.so.conf.d/njet.conf
%{_unitdir}/njet.service
%attr(-,njet,njet) /usr/local/njet/

%changelog
* Wed Nov 8 2023 hongxina <hongxina@tmlake.com> - 1.2.3-1
- update to 1.2.3 

* Wed Oct 18 2023 hongxina <hongxina@tmlake.com> - 1.2.2-1
- DESC: update to 1.2.2-1

* Tue Aug 15 2023 hongxina <hongxina@tmlake.com> - 1.1.2-1
- init 

