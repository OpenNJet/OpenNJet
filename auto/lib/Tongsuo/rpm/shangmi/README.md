Overview
========

Building the RPM with the `shangmi` directory spec will install babassl
into `/usr` to replace openssl in your system. There are some files needed
by RPM-packed in the `RPM/shangmi` directory.

- `babassl.spec`: the shangmi BabaSSL spec which is modified based
  on the openssl spec.

- `10001-apps-only-display-BabaSSL-version-in-the-openssl-ve.patch`: There are
  softwares or scripts that will check the version number of openssl through
  the `openssl version` command in the centos and other mainstream operating
  systems.
  So in order to keep compatibility, it's better that we display the BabaSSL
  version in the `openssl version -a` and `openssl version` only display the
  OpenSSL version during the RPM-packed.

- `10002-sync-babassl-version-number-up-with-openssl-1.1.1g-.patch`: `sshd`
  and other applications will check whether the version number of RPM-packed
  openssl is consistent with the original system. Therefore, when packaging,
  a similar patch is required to keep it consistent with the original system's
  openssl version number. Take this patch as an example. It is to solve the
  problem of inconsistent openssl version number in `openssl 1.1.1g-FIPS`
  systems (such as `anolis os 8.4`).

- `opensslconf-new.h` and `opensslconf-new-warning.h`: they are both brought
  from the `Openssl 1.1.1 rpm` repository. Do an `opensslconf.h` switcheroo to
  avoid file conflicts on systems where you can have both a `32-` and `64-bit`
  version of the library, and they each need their own correct-but-different
  versions of opensslconf.h to be usable.

- `Makefile.certificate`:  it is both brought from the `Openssl 1.1.1` rpm
  repository and will be installed in the
  `/usr/share/doc/openssl/Makefile.certificate`. It can generate keys and
  self-signed certs.

- `make-dummy-cert` and `renew-dummy-cert`: they are both brought from the
  `Openssl 1.1.1 rpm` repository. They are used for generating the keys and
  self-signed certs for the Redhat-compatible OSes. Besides, they are needed
  by some softwares or applications(such as `mod_ssl + httpd`).
