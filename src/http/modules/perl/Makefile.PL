
# Copyright (C) Igor Sysoev
# Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.

use 5.006001;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'njet',
    VERSION_FROM      => 'njet.pm',     # finds $VERSION
    PREREQ_PM         => {},             # e.g., Module::Name => 1.1

    ABSTRACT_FROM     => 'njet.pm',     # retrieve abstract from module
    AUTHOR            => 'Igor Sysoev',

    CCFLAGS           => "$ENV{NJT_PM_CFLAGS}",
    OPTIMIZE          => '-O',

    LDDLFLAGS         => "$ENV{NJT_PM_LDFLAGS}",

    INC               => join(" ", map {
                             m#^/# ? "-I $_" : "-I ../../../../../$_"
                         } (split /\s+/, $ENV{NJT_INCS})),

    depend => {
        'njet.c'     => join(" ", map {
                             m#^/# ? $_ : "../../../../../$_"
                         } (split(/\s+/, $ENV{NJT_DEPS}),
                            "src/http/modules/perl/njt_http_perl_module.h"))
    },

    PM => {
        'njet.pm'    => '$(INST_LIBDIR)/njet.pm'
    }
);
