#ref:https://fedoraproject.org/wiki/How_to_create_an_RPM_package
%define njet_home %{_localstatedir}/cache/njet
%define njet_user njet
%define njet_group njet

#redefine source directory location so we can place all sources in a subdirectory for easier management
%define _sourcedir /srv/njet_main

# distribution specific definitions
%define use_systemd (0%{?fedora} && 0%{?fedora} >= 18) || (0%{?rhel} && 0%{?rhel} >= 7)

%if 0%{?rhel}  == 5
Group: System Environment/Daemons
Requires(pre): shadow-utils
Requires: initscripts >= 8.36
Requires(post): chkconfig
%endif

%if 0%{?rhel}  == 6
Group: System Environment/Daemons
Requires(pre): shadow-utils
Requires: initscripts >= 8.36
Requires(post): chkconfig
%define with_spdy 1
%endif

%if 0%{?rhel}  == 7
Group: Application
Requires(pre): shadow-utils
Requires: systemd
BuildRequires: systemd
%define with_spdy 1
%endif

%if 0%{?suse_version}
Group: Productivity/Networking/Web/Servers
Requires(pre): pwdutils
%endif

# end of distribution specific definitions

Summary: TMLake
Name: njet
Version: 1.0
Release: R1
URL: https://www.tmlake.com/
Packager: TMLake
Vendor: TMLake




Source6: build/rpm/njet.upgrade.sh


License: Proprietary

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: zlib-devel

Provides: webserver

%description
Extends NGINX open source to create an enterprise-grade
Application Delivery Controller, and Web Server. Enhanced
features include: Layer 4 and Layer 7 load balancing with health checks,
session persistence and dynamic upstream configuration; Improved content caching, sorted URI.

%package debug
Summary: TMLake
Group: TMLake
Requires: njet
%description debug

%prep
#%setup -q
#%setup -T -D -a 0

%build
cd %{_sourcedir} && ./build_cc.sh conf %{getenv:CI_COMMIT_SHA}
cd %{_sourcedir} && %{__make} %{?_smp_mflags}
%{__mkdir} -p %{_builddir}/%{name}-%{version}/objs/
%{__cp} %{_sourcedir}/objs/njet  %{_builddir}/%{name}-%{version}/objs/njet
%{__cp} %{_sourcedir}/objs/njet  %{_builddir}/%{name}-%{version}/objs/njet.debug

%install
%{__rm} -rf $RPM_BUILD_ROOT
cd %{_sourcedir} && %{__make} DESTDIR=$RPM_BUILD_ROOT install

%{__mkdir} -p $RPM_BUILD_ROOT%{_datadir}/njet
%{__mv} $RPM_BUILD_ROOT%{_sysconfdir}/njet/html $RPM_BUILD_ROOT%{_datadir}/njet/

%{__rm} -f $RPM_BUILD_ROOT%{_sysconfdir}/njet/*.default
%{__rm} -f $RPM_BUILD_ROOT%{_sysconfdir}/njet/fastcgi.conf

%{__mkdir} -p $RPM_BUILD_ROOT%{_localstatedir}/log/njet
%{__mkdir} -p $RPM_BUILD_ROOT%{_localstatedir}/run/njet
%{__mkdir} -p $RPM_BUILD_ROOT%{_localstatedir}/cache/njet

%{__mkdir} -p $RPM_BUILD_ROOT%{_sysconfdir}/njet/conf.d
%{__rm} $RPM_BUILD_ROOT%{_sysconfdir}/njet/njet.conf
%{__install} -m 644 -p %{_sourcedir}/build/rpm/njet.conf \
   $RPM_BUILD_ROOT%{_sysconfdir}/njet/njet.conf

%{__mkdir} -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
%{__install} -m 644 -p %{_sourcedir}/build/rpm/njet.sysconf \
   $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/njet

   
%if %{use_systemd}
# install systemd-specific files
%{__mkdir} -p $RPM_BUILD_ROOT%{_unitdir}
%{__install} -m644 %{_sourcedir}/build/rpm/njet.service \
        $RPM_BUILD_ROOT%{_unitdir}/njet.service
%{__mkdir} -p $RPM_BUILD_ROOT%{_libexecdir}/initscripts/legacy-actions/njet
%{__install} -m755 %{_sourcedir}/build/rpm/njet.upgrade.sh \
        $RPM_BUILD_ROOT%{_libexecdir}/initscripts/legacy-actions/njet/upgrade
%else
# install SYSV init stuff
%{__mkdir} -p $RPM_BUILD_ROOT%{_initrddir}
%{__install} -m755 %{_sourcedir}/build/rpm/njet.init \
   $RPM_BUILD_ROOT%{_initrddir}/njet
%endif

# install log rotation stuff
%{__mkdir} -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
%{__install} -m 644 -p %{_sourcedir}/build/rpm/logrotate \
   $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/njet
%{__install} -m644 %{_builddir}/%{name}-%{version}/objs/njet.debug \
   $RPM_BUILD_ROOT%{_sbindir}/njet.debug

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

%{_sbindir}/njet

%dir %{_sysconfdir}/njet
%dir %{_sysconfdir}/njet/conf.d


%config(noreplace) %{_sysconfdir}/njet/njet.conf
%config(noreplace) %{_sysconfdir}/njet/mime.types
%config(noreplace) %{_sysconfdir}/njet/fastcgi_params
%config(noreplace) %{_sysconfdir}/njet/scgi_params
%config(noreplace) %{_sysconfdir}/njet/uwsgi_params
%config(noreplace) %{_sysconfdir}/njet/koi-utf
%config(noreplace) %{_sysconfdir}/njet/koi-win
%config(noreplace) %{_sysconfdir}/njet/win-utf

%config(noreplace) %{_sysconfdir}/logrotate.d/njet
%config(noreplace) %{_sysconfdir}/sysconfig/njet
#add core rules file


%if %{use_systemd}
%{_unitdir}/njet.service
%dir %{_libexecdir}/initscripts/legacy-actions/njet
%{_libexecdir}/initscripts/legacy-actions/njet/*
%else
%{_initrddir}/njet
%endif

%dir %{_datadir}/njet
%dir %{_datadir}/njet/html
%{_datadir}/njet/html/*

%attr(0755,root,root) %dir %{_localstatedir}/cache/njet
%attr(0755,root,root) %dir %{_localstatedir}/log/njet

%files debug
%attr(0755,root,root) %{_sbindir}/njet.debug

%pre
# Add the "njet" user
getent group %{njet_group} >/dev/null || groupadd -r %{njet_group}
getent passwd %{njet_user} >/dev/null || \
    useradd -r -g %{njet_group} -s /sbin/nologin \
    -d %{njet_home} -c "njet user"  %{njet_user}
exit 0

%post
# Register the njet service
useradd -s /sbin/nologin njet  -M  
if [ $1 -eq 1 ]; then
%if %{use_systemd}
    /usr/bin/systemctl preset njet.service >/dev/null 2>&1 ||:
%else
    /sbin/chkconfig --add njet
%endif
    # print site info
    cat <<BANNER
----------------------------------------------------------------------
Thanks for using njet!
----------------------------------------------------------------------
BANNER

    # Touch and set permisions on default log files on installation

    if [ -d %{_localstatedir}/log/njet ]; then
        if [ ! -e %{_localstatedir}/log/njet/access.log ]; then
            touch %{_localstatedir}/log/njet/access.log
            %{__chmod} 640 %{_localstatedir}/log/njet/access.log
            %{__chown} njet:adm %{_localstatedir}/log/njet/access.log
        fi

        if [ ! -e %{_localstatedir}/log/njet/error.log ]; then
            touch %{_localstatedir}/log/njet/error.log
            %{__chmod} 640 %{_localstatedir}/log/njet/error.log
            %{__chown} njet:adm %{_localstatedir}/log/njet/error.log
        fi
    fi
fi

%preun
if [ $1 -eq 0 ]; then
%if %use_systemd
    /usr/bin/systemctl --no-reload disable njet.service >/dev/null 2>&1 ||:
    /usr/bin/systemctl stop njet.service >/dev/null 2>&1 ||:
%else
    /sbin/service njet stop > /dev/null 2>&1
    /sbin/chkconfig --del njet
%endif
fi

%postun
%if %use_systemd
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 ||:
%endif
if [ $1 -ge 1 ]; then
    /sbin/service njet status  >/dev/null 2>&1 || exit 0
    /sbin/service njet upgrade >/dev/null 2>&1 || echo \
        "Binary upgrade failed, please check njet's error.log"
fi

%changelog
