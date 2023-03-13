include_directories(../..//auto/lib/tassl/include ${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/src
		${mosquitto_SOURCE_DIR}/include ${mosquitto_SOURCE_DIR}/lib
		${OPENSSL_INCLUDE_DIR} ${STDBOOL_H_PATH} ${STDINT_H_PATH} )
link_directories(../../auto/lib/tassl)

set (MOSQ_SRCS
	../lib/mosquitto_internal.h
	../lib/actions.c
	../lib/alias_mosq.c 
	../lib/alias_mosq.h
	../lib/connect.c
	../lib/handle_auth.c
	../lib/handle_connack.c
	../lib/handle_disconnect.c
	../lib/handle_ping.c
	../lib/handle_pubackcomp.c
	../lib/handle_publish.c
	../lib/handle_pubrec.c
	../lib/handle_pubrel.c
	../lib/handle_suback.c
	../lib/handle_unsuback.c
	../lib/helpers.c
	../lib/logging_mosq.c ../lib/logging_mosq.h
	../lib/loop.c
	../lib/memory_mosq.c ../lib/memory_mosq.h
	../lib/messages_mosq.c ../lib/messages_mosq.h
	../lib/misc_mosq.c ../lib/misc_mosq.h
	../lib/mosquitto.c ../include/mosquitto.h
	../include/mqtt_protocol.h
	../lib/net_mosq_ocsp.c ../lib/net_mosq.c ../lib/net_mosq.h
	../lib/options.c
	../lib/packet_datatypes.c
	../lib/packet_mosq.c ../lib/packet_mosq.h
	../lib/property_mosq.c ../lib/property_mosq.h
	../lib/read_handle.c ../lib/read_handle.h
	../lib/send_connect.c
	../lib/send_disconnect.c
	../lib/send_mosq.c
	../lib/send_publish.c
	../lib/send_subscribe.c
	../lib/send_unsubscribe.c
	../lib/send_mosq.c ../lib/send_mosq.h
	../lib/srv_mosq.c
	../lib/strings_mosq.c
	../lib/thread_mosq.c
	../lib/time_mosq.c
	../lib/tls_mosq.c
	../lib/utf8_mosq.c
	../lib/util_mosq.c ../lib/util_topic.c ../lib/util_mosq.h
	../lib/will_mosq.c ../lib/will_mosq.h
	../lib/callbacks.c
	njet_iot_memory_mosq.c
	njet_iot_send_disconnect.c
	njet_iot_handle_suback.c
	njet_iot_handle_connect.c
	njet_iot_send_subscribe.c
	njet_iot_handle_ping.c
	njet_iot_handle_pubrel.c
	njet_iot_handle_pubackcomp.c
	njet_iot_send_unsuback.c
	njet_iot_send_connect.c
	njet_iot_send_publish.c
	njet_iot_util_mosq.c njet_iot_util_mosq.h
	njet_iot_will_mosq.c njet_iot_will_mosq.h
	njet_bridge.c 
	njet_bridge_topic.c
	njet_iot_conf.c
	njet_iot_conf_includedir.c
	njet_iot_context.c
	njet_iot_control.c
	njet_iot_database.c
	njet_iot_handle_auth.c
	njet_iot_handle_connack.c
	njet_iot_handle_connect.c
	njet_iot_handle_disconnect.c
	njet_iot_handle_publish.c
	njet_iot_handle_subscribe.c
	njet_iot_handle_unsubscribe.c
	njet_iot_keepalive.c
	njet_iot_lib_load.h
	njet_iot_logging.c
	njet_iot_loop.c
	njet_iot_memory_public.c
	njet_iot_internal.h
	njet_iot_mux.c njet_iot_mux.h njet_iot_mux_epoll.c 
	njet_iot_net_mosq.c njet_iot_net_mosq.h 
	njet_iot_send_mosq.c njet_iot_send_mosq.h 
	njet_iot_send_unsubscribe.c
	njet_iot_send_suback.c
	njet_iot_handle_pubrec.c
	njet_iot_handle_unsuback.c
	njet_iot_packet_mosq.c njet_iot_packet_mosq.h 
	njet_iot_alias_mosq.c njet_iot_alias_mosq.h 
	njet_iot_read_handle.c njet_iot_read_handle.h
	njet_iot_password_mosq.c 
	njet_iot_password_mosq.h
	njet_iot_persis_read_v234.c 
	njet_iot_persis_read_v5.c 
	njet_iot_persis_read.c
	njet_iot_persis_write_v5.c 
	njet_iot_persis_write.c
	njet_iot_persis.h
	njet_iot_plugin.c 
	njet_iot_plugin_public.c
	njet_iot_property.c
	njet_iot_read_handle.c
	njet_iot_retain.c
	njet_iot_security.c njet_iot_security_default.c
	njet_iot_send_auth.c
	njet_iot_send_connack.c
	njet_iot_send_suback.c
	njet_iot_send_unsuback.c
	njet_iot_session_expiry.c
	njet_iot_subs.c
	njet_iot_net.c
	njet_iot_sys_tree.c njet_iot_sys_tree.h
	njet_iot_topic_tok.c
	njet_iot_will_delay.c
	njet_iot_emb.c njet_iot_emb.h
	lmdb.h midl.h midl.c mdb.c
	njet_iot_client_emb.c 
	njet_iot_shared.c njet_iot_shared.h
	njet_iot_client_props.c
	njet_iot_client_conf.c
	)
#websocddkets.c
#hhsignals.c


if (WITH_BUNDLED_DEPS)
	include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/deps)
endif (WITH_BUNDLED_DEPS)

find_path(HAVE_SYS_EPOLL_H sys/epoll.h)
if (HAVE_SYS_EPOLL_H)
	add_definitions("-DWITH_EPOLL")
endif()

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if (INC_BRIDGE_SUPPORT)
	set (MOSQ_SRCS ${MOSQ_SRCS} njet_bridge.c)
	add_definitions("-DWITH_BRIDGE -g")
endif (INC_BRIDGE_SUPPORT)


option(USE_LIBWRAP
	"Include tcp-wrappers support?" OFF)

if (USE_LIBWRAP)
	set (MOSQ_LIBS ${MOSQ_LIBS} wrap)
	add_definitions("-DWITH_WRAP")
endif (USE_LIBWRAP)

option(INC_DB_UPGRADE
	"Include database upgrade support? (recommended)" ON)

option(INC_MEMTRACK
	"Include memory tracking support?" ON)
if (INC_MEMTRACK)
	add_definitions("-DWITH_MEMORY_TRACKING")
endif (INC_MEMTRACK)

option(WITH_PERSISTENCE
	"Include persistence support?" ON)
if (WITH_PERSISTENCE)
	add_definitions("-DWITH_PERSISTENCE")
endif (WITH_PERSISTENCE)

option(WITH_SYS_TREE
	"Include $SYS tree support?" ON)
if (WITH_SYS_TREE)
	add_definitions("-DWITH_SYS_TREE")
endif (WITH_SYS_TREE)

option(WITH_ADNS
	"Include ADNS support?" OFF)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	option(WITH_SYSTEMD
		"Include systemd support?" OFF)
	if (WITH_SYSTEMD)
		add_definitions("-DWITH_SYSTEMD")
		find_library(SYSTEMD_LIBRARY systemd)
		set (MOSQ_LIBS ${MOSQ_LIBS} ${SYSTEMD_LIBRARY})
	endif (WITH_SYSTEMD)
endif (CMAKE_SYSTEM_NAME STREQUAL Linux)

option(WITH_WEBSOCKETS "Include websockets support?" OFF)
option(STATIC_WEBSOCKETS "Use the static libwebsockets library?" OFF)
if (WITH_WEBSOCKETS)
	find_package(libwebsockets)
	add_definitions("-DWITH_WEBSOCKETS")
endif (WITH_WEBSOCKETS)

option(WITH_CONTROL "Include $CONTROL topic support?" ON)
if (WITH_CONTROL)
	add_definitions("-DWITH_CONTROL")
endif (WITH_CONTROL)


if (WIN32 OR CYGWIN)
	set (MOSQ_SRCS ${MOSQ_SRCS} service.c)
endif (WIN32 OR CYGWIN)

#add_definitions (-DWITH_BROKER)
#because we build for both client & server ,so must not define with_broker

if (WITH_DLT)
    message(STATUS "DLT_LIBDIR = ${DLT_LIBDIR}")
    link_directories(${DLT_LIBDIR})
    set (MOSQ_LIBS ${MOSQ_LIBS} ${DLT_LIBRARIES})
endif (WITH_DLT)

set (MOSQ_LIBS ${MOSQ_LIBS} ${OPENSSL_LIBRARIES} )
# Check for getaddrinfo_a
include(CheckLibraryExists)
check_library_exists(anl getaddrinfo_a  "" HAVE_GETADDRINFO_A)
if (HAVE_GETADDRINFO_A AND WITH_ADNS)
	add_definitions("-DWITH_ADNS")
	add_definitions(-DHAVE_GETADDRINFO_A)
	set (MOSQ_LIBS ${MOSQ_LIBS} anl)
endif (HAVE_GETADDRINFO_A AND WITH_ADNS)


if (UNIX)
	if (APPLE)
		set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	    set (MOSQ_LIBS ${MOSQ_LIBS} m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
		set (MOSQ_LIBS ${MOSQ_LIBS} m)
    elseif(QNX)
        set(MOSQ_LIBS ${MOSQ_LIBS} m socket)
    else(APPLE)
        set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
        find_library(LIBRT rt)
        if (LIBRT)
            set (MOSQ_LIBS ${MOSQ_LIBS} rt)
        endif (LIBRT)
    endif (APPLE)
endif (UNIX)

if (WIN32)
	set (MOSQ_LIBS ${MOSQ_LIBS} ws2_32)
endif (WIN32)

if (WITH_WEBSOCKETS)
	if (STATIC_WEBSOCKETS)
		set (MOSQ_LIBS ${MOSQ_LIBS} websockets_static)
		if (WIN32)
			set (MOSQ_LIBS ${MOSQ_LIBS} iphlpapi)
			link_directories(${mosquitto_SOURCE_DIR})
		endif (WIN32)
	else (STATIC_WEBSOCKETS)
		set (MOSQ_LIBS ${MOSQ_LIBS} websockets)
	endif (STATIC_WEBSOCKETS)
endif (WITH_WEBSOCKETS)

add_library(njetmq SHARED ${MOSQ_SRCS})
#add_executable(mosquitto ${MOSQ_SRCS})
target_link_libraries(njetmq ${MOSQ_LIBS})

if (UNIX)
	if (APPLE)
		set_target_properties(njetmq PROPERTIES LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/linker-macosx.syms")
	else (APPLE)
		set_target_properties(njetmq PROPERTIES LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/linker.syms")
	endif (APPLE)
endif (UNIX)

install(TARGETS njetmq  DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES njet_iot_emb.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
