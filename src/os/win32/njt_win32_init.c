
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>


njt_uint_t  njt_win32_version;
njt_uint_t  njt_ncpu;
njt_uint_t  njt_max_wsabufs;
njt_int_t   njt_max_sockets;
njt_uint_t  njt_inherited_nonblocking = 1;
njt_uint_t  njt_tcp_nodelay_and_tcp_nopush;

char        njt_unique[NJT_INT32_LEN + 1];


njt_os_io_t njt_os_io = {
    njt_wsarecv,
    njt_wsarecv_chain,
    njt_udp_wsarecv,
    njt_wsasend,
    NULL,
    NULL,
    njt_wsasend_chain,
    0
};


typedef struct {
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType;
} njt_osviex_stub_t;


static u_int               osviex;
static OSVERSIONINFOEX     osvi;

/* Should these pointers be per protocol ? */
LPFN_ACCEPTEX              njt_acceptex;
LPFN_GETACCEPTEXSOCKADDRS  njt_getacceptexsockaddrs;
LPFN_TRANSMITFILE          njt_transmitfile;
LPFN_TRANSMITPACKETS       njt_transmitpackets;
LPFN_CONNECTEX             njt_connectex;
LPFN_DISCONNECTEX          njt_disconnectex;

static GUID ax_guid = WSAID_ACCEPTEX;
static GUID as_guid = WSAID_GETACCEPTEXSOCKADDRS;
static GUID tf_guid = WSAID_TRANSMITFILE;
static GUID tp_guid = WSAID_TRANSMITPACKETS;
static GUID cx_guid = WSAID_CONNECTEX;
static GUID dx_guid = WSAID_DISCONNECTEX;


#if (NJT_LOAD_WSAPOLL)
njt_wsapoll_pt             WSAPoll;
njt_uint_t                 njt_have_wsapoll;
#endif


njt_int_t
njt_os_init(njt_log_t *log)
{
    DWORD         bytes;
    SOCKET        s;
    WSADATA       wsd;
    njt_err_t     err;
    njt_time_t   *tp;
    njt_uint_t    n;
    SYSTEM_INFO   si;

    /* get Windows version */

    njt_memzero(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

    osviex = GetVersionEx((OSVERSIONINFO *) &osvi);

    if (osviex == 0) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (GetVersionEx((OSVERSIONINFO *) &osvi) == 0) {
            njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                          "GetVersionEx() failed");
            return NJT_ERROR;
        }
    }

#ifdef _MSC_VER
#pragma warning(default:4996)
#endif

    /*
     *  Windows 3.1 Win32s   0xxxxx
     *
     *  Windows 95           140000
     *  Windows 98           141000
     *  Windows ME           149000
     *  Windows NT 3.51      235100
     *  Windows NT 4.0       240000
     *  Windows NT 4.0 SP5   240050
     *  Windows 2000         250000
     *  Windows XP           250100
     *  Windows 2003         250200
     *  Windows Vista/2008   260000
     *
     *  Windows CE x.x       3xxxxx
     */

    njt_win32_version = osvi.dwPlatformId * 100000
                        + osvi.dwMajorVersion * 10000
                        + osvi.dwMinorVersion * 100;

    if (osviex) {
        njt_win32_version += osvi.wServicePackMajor * 10
                             + osvi.wServicePackMinor;
    }

    GetSystemInfo(&si);
    njt_pagesize = si.dwPageSize;
    njt_allocation_granularity = si.dwAllocationGranularity;
    njt_ncpu = si.dwNumberOfProcessors;
    njt_cacheline_size = NJT_CPU_CACHE_LINE;

    for (n = njt_pagesize; n >>= 1; njt_pagesize_shift++) { /* void */ }

    /* delete default "C" locale for _wcsicmp() */
    setlocale(LC_ALL, "");


    /* init Winsock */

    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                      "WSAStartup() failed");
        return NJT_ERROR;
    }

    if (njt_win32_version < NJT_WIN_NT) {
        njt_max_wsabufs = 16;
        return NJT_OK;
    }

    /* STUB: njt_uint_t max */
    njt_max_wsabufs = 1024 * 1024;

    /*
     * get AcceptEx(), GetAcceptExSockAddrs(), TransmitFile(),
     * TransmitPackets(), ConnectEx(), and DisconnectEx() addresses
     */

    s = njt_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (s == (njt_socket_t) -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                      njt_socket_n " failed");
        return NJT_ERROR;
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &ax_guid, sizeof(GUID),
                 &njt_acceptex, sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL)
        == -1)
    {
        njt_log_error(NJT_LOG_NOTICE, log, njt_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_ACCEPTEX) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &as_guid, sizeof(GUID),
                 &njt_getacceptexsockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
                 &bytes, NULL, NULL)
        == -1)
    {
        njt_log_error(NJT_LOG_NOTICE, log, njt_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_GETACCEPTEXSOCKADDRS) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tf_guid, sizeof(GUID),
                 &njt_transmitfile, sizeof(LPFN_TRANSMITFILE), &bytes,
                 NULL, NULL)
        == -1)
    {
        njt_log_error(NJT_LOG_NOTICE, log, njt_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_TRANSMITFILE) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tp_guid, sizeof(GUID),
                 &njt_transmitpackets, sizeof(LPFN_TRANSMITPACKETS), &bytes,
                 NULL, NULL)
        == -1)
    {
        njt_log_error(NJT_LOG_NOTICE, log, njt_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_TRANSMITPACKETS) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &cx_guid, sizeof(GUID),
                 &njt_connectex, sizeof(LPFN_CONNECTEX), &bytes,
                 NULL, NULL)
        == -1)
    {
        njt_log_error(NJT_LOG_NOTICE, log, njt_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_CONNECTEX) failed");
    }

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &dx_guid, sizeof(GUID),
                 &njt_disconnectex, sizeof(LPFN_DISCONNECTEX), &bytes,
                 NULL, NULL)
        == -1)
    {
        njt_log_error(NJT_LOG_NOTICE, log, njt_socket_errno,
                      "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
                               "WSAID_DISCONNECTEX) failed");
    }

    if (njt_close_socket(s) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_socket_errno,
                      njt_close_socket_n " failed");
    }

#if (NJT_LOAD_WSAPOLL)
    {
    HMODULE  hmod;

    hmod = GetModuleHandle("ws2_32.dll");
    if (hmod == NULL) {
        njt_log_error(NJT_LOG_NOTICE, log, njt_errno,
                      "GetModuleHandle(\"ws2_32.dll\") failed");
        goto nopoll;
    }

    WSAPoll = (njt_wsapoll_pt) (void *) GetProcAddress(hmod, "WSAPoll");
    if (WSAPoll == NULL) {
        njt_log_error(NJT_LOG_NOTICE, log, njt_errno,
                      "GetProcAddress(\"WSAPoll\") failed");
        goto nopoll;
    }

    njt_have_wsapoll = 1;

    }

nopoll:

#endif

    if (GetEnvironmentVariable("njt_unique", njt_unique, NJT_INT32_LEN + 1)
        != 0)
    {
        njt_process = NJT_PROCESS_WORKER;

    } else {
        err = njt_errno;

        if (err != ERROR_ENVVAR_NOT_FOUND) {
            njt_log_error(NJT_LOG_EMERG, log, err,
                          "GetEnvironmentVariable(\"njt_unique\") failed");
            return NJT_ERROR;
        }

        njt_sprintf((u_char *) njt_unique, "%P%Z", njt_pid);
    }

    tp = njt_timeofday();
    srand((njt_pid << 16) ^ (unsigned) tp->sec ^ tp->msec);

    return NJT_OK;
}


void
njt_os_status(njt_log_t *log)
{
    njt_osviex_stub_t  *osviex_stub;

    njt_log_error(NJT_LOG_NOTICE, log, 0, NJT_VER_BUILD);

    if (osviex) {

        /*
         * the MSVC 6.0 SP2 defines wSuiteMask and wProductType
         * as WORD wReserved[2]
         */
        osviex_stub = (njt_osviex_stub_t *) &osvi.wServicePackMinor;

        njt_log_error(NJT_LOG_INFO, log, 0,
                      "OS: %ui build:%ud, \"%s\", suite:%Xd, type:%ud",
                      njt_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
                      osviex_stub->wSuiteMask, osviex_stub->wProductType);

    } else {
        if (osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {

            /* Win9x build */

            njt_log_error(NJT_LOG_INFO, log, 0,
                          "OS: %ui build:%ud.%ud.%ud, \"%s\"",
                          njt_win32_version,
                          osvi.dwBuildNumber >> 24,
                          (osvi.dwBuildNumber >> 16) & 0xff,
                          osvi.dwBuildNumber & 0xffff,
                          osvi.szCSDVersion);

        } else {

            /*
             * VER_PLATFORM_WIN32_NT
             *
             * we do not currently support VER_PLATFORM_WIN32_CE
             * and we do not support VER_PLATFORM_WIN32s at all
             */

            njt_log_error(NJT_LOG_INFO, log, 0, "OS: %ui build:%ud, \"%s\"",
                          njt_win32_version, osvi.dwBuildNumber,
                          osvi.szCSDVersion);
        }
    }
}
