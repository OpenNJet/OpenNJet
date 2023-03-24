FROM centos:7
RUN rm -rf /etc/yum.repos.d/*.repo 
COPY ./repos/*.repo /etc/yum.repos.d/
RUN yum clean all && yum makecache && \
                yum install -y gcc gcc-c++ \
                libtool libtool-ltdl cmake3 \
                make cmake perl perl-CPAN \
                zlib-devel cmake perl-IPC-Cmd \
                pkgconfig make vim-common \
                sudo m4 deltarpm openssl-devel \
                automake autoconf \
                libasan libasan-static \
                yum-utils rpm-build && \
    yum clean all

RUN useradd builder -u 1000 -m -G users,wheel && \
    echo "builder ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    echo "# macros"                      >  /home/builder/.rpmmacros && \
    echo "%_topdir    /home/builder/rpm" >> /home/builder/.rpmmacros && \
    echo "%_sourcedir %{_topdir}"        >> /home/builder/.rpmmacros && \
    echo "%_builddir  %{_topdir}"        >> /home/builder/.rpmmacros && \
    echo "%_specdir   %{_topdir}"        >> /home/builder/.rpmmacros && \
    echo "%_rpmdir    %{_topdir}"        >> /home/builder/.rpmmacros && \
    echo "%_srcrpmdir %{_topdir}"        >> /home/builder/.rpmmacros && \
    mkdir /home/builder/rpm && \
    chown -R builder /home/builder

#USER builder
ENV FLAVOR=rpmbuild OS=centos DIST=el7
CMD /srv/pkg
