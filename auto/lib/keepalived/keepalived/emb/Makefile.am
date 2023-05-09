# Makefile.am
#
# Keepalived OpenSource project.
#

AM_CPPFLAGS		= -I $(top_srcdir)/keepalived/include -I $(top_srcdir)/lib
AM_CPPFLAGS		+= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)

lib_LTLIBRARIES =libha_emb.la

#libha_emb_a_SOURCES 
#    ../vrrp/vrrp_daemon.c 
VRRP_SOURCES   = \
	../vrrp/vrrp_notify.c \
	../vrrp/vrrp_print.c \
	../vrrp/vrrp_data.c \
	../vrrp/vrrp_parser.c \
    ../vrrp/vrrp.c \
	../vrrp/vrrp_scheduler.c \
	../vrrp/vrrp_sync.c \
    ../vrrp/vrrp_arp.c \
	../vrrp/vrrp_if.c \
	../vrrp/vrrp_track.c \
	../vrrp/vrrp_ipaddress.c \
    ../vrrp/vrrp_ndisc.c \
	../vrrp/vrrp_if_config.c \
	../vrrp/vrrp_static_track.c \
    ../vrrp/vrrp_iproute.c \
	../vrrp/vrrp_iprule.c \
	../vrrp/vrrp_ip_rule_route_parser.c \
	../vrrp/vrrp_vmac.c \
	../vrrp/vrrp_ipsecah.c 

TRACK_SOURCES = ../trackers/track_file.c
BASE_SOURCES = \
	../../lib/memory.c ../../lib/utils.c ../../lib/notify.c ../../lib/timer.c ../../lib/scheduler.c \
              ../../lib/vector.c ../../lib/html.c ../../lib/parser.c ../../lib/signals.c ../../lib/logger.c \
              ../../lib/list_head.c ../../lib/rbtree.c ../../lib/process.c ../../lib/json_writer.c \
              ../../lib/bitops.h ../../lib/timer.h ../../lib/scheduler.h ../../lib/vector.h ../../lib/parser.h \
              ../../lib/signals.h ../../lib/notify.h ../../lib/logger.h ../../lib/memory.h ../../lib/html.h ../../lib/utils.h \
              ../../lib/keepalived_magic.h ../../lib/list_head.h ../../lib/rbtree_ka.h ../../lib/rbtree.h \
              ../../lib/rbtree_types.h ../../lib/process.h ../../lib/rbtree_augmented.h ../../lib/assert_debug.h \
              ../../lib/json_writer.h ../../lib/warnings.h ../../lib/container.h ../../lib/align.h ../../lib/sockaddr.h \
			  ../../lib/rttables.c ../../lib/rttables.h \
			  ../../lib/assert.c
libha_emb_la_SOURCES	= \
	njt_vrrp_emb.c njt_vrrp_daemon.c \
	../core/global_data.c \
	../core/keepalived_netlink.c \
	../core/layer4.c \
	../core/global_parser.c \
	../core/config_notify.c \
	../core/pidfile.c \
	../core/reload_monitor.c \
	../core/smtp.c 

libha_emb_la_SOURCES	+= ../include/vrrp_daemon.h
libha_emb_la_SOURCES	+=  $(VRRP_SOURCES)
libha_emb_la_SOURCES	+=  $(TRACK_SOURCES)
libha_emb_la_SOURCES	+=  $(BASE_SOURCES)

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
