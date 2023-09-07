
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SOCKET_H_INCLUDED_
#define _NJT_SOCKET_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_WRITE_SHUTDOWN SD_SEND
#define NJT_READ_SHUTDOWN  SD_RECEIVE
#define NJT_RDWR_SHUTDOWN  SD_BOTH


typedef SOCKET  njt_socket_t;
typedef int     socklen_t;


#define njt_socket(af, type, proto)                                          \
    WSASocketW(af, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED)

#define njt_socket_n        "WSASocketW()"

int njt_nonblocking(njt_socket_t s);
int njt_blocking(njt_socket_t s);

#define njt_nonblocking_n   "ioctlsocket(FIONBIO)"
#define njt_blocking_n      "ioctlsocket(!FIONBIO)"

int njt_socket_nread(njt_socket_t s, int *n);
#define njt_socket_nread_n  "ioctlsocket(FIONREAD)"

#define njt_shutdown_socket    shutdown
#define njt_shutdown_socket_n  "shutdown()"

#define njt_close_socket    closesocket
#define njt_close_socket_n  "closesocket()"


#ifndef WSAID_ACCEPTEX

typedef BOOL (PASCAL FAR * LPFN_ACCEPTEX)(
    IN SOCKET sListenSocket,
    IN SOCKET sAcceptSocket,
    IN PVOID lpOutputBuffer,
    IN DWORD dwReceiveDataLength,
    IN DWORD dwLocalAddressLength,
    IN DWORD dwRemoteAddressLength,
    OUT LPDWORD lpdwBytesReceived,
    IN LPOVERLAPPED lpOverlapped
    );

#define WSAID_ACCEPTEX                                                       \
    {0xb5367df1,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}

#endif


#ifndef WSAID_GETACCEPTEXSOCKADDRS

typedef VOID (PASCAL FAR * LPFN_GETACCEPTEXSOCKADDRS)(
    IN PVOID lpOutputBuffer,
    IN DWORD dwReceiveDataLength,
    IN DWORD dwLocalAddressLength,
    IN DWORD dwRemoteAddressLength,
    OUT struct sockaddr **LocalSockaddr,
    OUT LPINT LocalSockaddrLength,
    OUT struct sockaddr **RemoteSockaddr,
    OUT LPINT RemoteSockaddrLength
    );

#define WSAID_GETACCEPTEXSOCKADDRS                                           \
        {0xb5367df2,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}

#endif


#ifndef WSAID_TRANSMITFILE

#ifndef TF_DISCONNECT

#define TF_DISCONNECT           1
#define TF_REUSE_SOCKET         2
#define TF_WRITE_BEHIND         4
#define TF_USE_DEFAULT_WORKER   0
#define TF_USE_SYSTEM_THREAD    16
#define TF_USE_KERNEL_APC       32

typedef struct _TRANSMIT_FILE_BUFFERS {
    LPVOID Head;
    DWORD HeadLength;
    LPVOID Tail;
    DWORD TailLength;
} TRANSMIT_FILE_BUFFERS, *PTRANSMIT_FILE_BUFFERS, FAR *LPTRANSMIT_FILE_BUFFERS;

#endif

typedef BOOL (PASCAL FAR * LPFN_TRANSMITFILE)(
    IN SOCKET hSocket,
    IN HANDLE hFile,
    IN DWORD nNumberOfBytesToWrite,
    IN DWORD nNumberOfBytesPerSend,
    IN LPOVERLAPPED lpOverlapped,
    IN LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    IN DWORD dwReserved
    );

#define WSAID_TRANSMITFILE                                                   \
    {0xb5367df0,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}

#endif


#ifndef WSAID_TRANSMITPACKETS

/* OpenWatcom has a swapped TP_ELEMENT_FILE and TP_ELEMENT_MEMORY definition */

#ifndef TP_ELEMENT_FILE

#ifdef _MSC_VER
#pragma warning(disable:4201) /* Nonstandard extension, nameless struct/union */
#endif

typedef struct _TRANSMIT_PACKETS_ELEMENT {
    ULONG dwElFlags;
#define TP_ELEMENT_MEMORY   1
#define TP_ELEMENT_FILE     2
#define TP_ELEMENT_EOP      4
    ULONG cLength;
    union {
        struct {
            LARGE_INTEGER nFileOffset;
            HANDLE        hFile;
        };
        PVOID             pBuffer;
    };
} TRANSMIT_PACKETS_ELEMENT, *PTRANSMIT_PACKETS_ELEMENT,
    FAR *LPTRANSMIT_PACKETS_ELEMENT;

#ifdef _MSC_VER
#pragma warning(default:4201)
#endif

#endif

typedef BOOL (PASCAL FAR * LPFN_TRANSMITPACKETS) (
    SOCKET hSocket,
    TRANSMIT_PACKETS_ELEMENT *lpPacketArray,
    DWORD nElementCount,
    DWORD nSendSize,
    LPOVERLAPPED lpOverlapped,
    DWORD dwFlags
    );

#define WSAID_TRANSMITPACKETS                                                \
    {0xd9689da0,0x1f90,0x11d3,{0x99,0x71,0x00,0xc0,0x4f,0x68,0xc8,0x76}}

#endif


#ifndef WSAID_CONNECTEX

typedef BOOL (PASCAL FAR * LPFN_CONNECTEX) (
    IN SOCKET s,
    IN const struct sockaddr FAR *name,
    IN int namelen,
    IN PVOID lpSendBuffer OPTIONAL,
    IN DWORD dwSendDataLength,
    OUT LPDWORD lpdwBytesSent,
    IN LPOVERLAPPED lpOverlapped
    );

#define WSAID_CONNECTEX \
    {0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}

#endif


#ifndef WSAID_DISCONNECTEX

typedef BOOL (PASCAL FAR * LPFN_DISCONNECTEX) (
    IN SOCKET s,
    IN LPOVERLAPPED lpOverlapped,
    IN DWORD  dwFlags,
    IN DWORD  dwReserved
    );

#define WSAID_DISCONNECTEX                                                   \
    {0x7fda2e11,0x8630,0x436f,{0xa0,0x31,0xf5,0x36,0xa6,0xee,0xc1,0x57}}

#endif


extern LPFN_ACCEPTEX              njt_acceptex;
extern LPFN_GETACCEPTEXSOCKADDRS  njt_getacceptexsockaddrs;
extern LPFN_TRANSMITFILE          njt_transmitfile;
extern LPFN_TRANSMITPACKETS       njt_transmitpackets;
extern LPFN_CONNECTEX             njt_connectex;
extern LPFN_DISCONNECTEX          njt_disconnectex;


#if (NJT_HAVE_POLL && !defined POLLIN)

/*
 * WSAPoll() is only available if _WIN32_WINNT >= 0x0600.
 * If it is not available during compilation, we try to
 * load it dynamically at runtime.
 */

#define NJT_LOAD_WSAPOLL 1

#define POLLRDNORM  0x0100
#define POLLRDBAND  0x0200
#define POLLIN      (POLLRDNORM | POLLRDBAND)
#define POLLPRI     0x0400

#define POLLWRNORM  0x0010
#define POLLOUT     (POLLWRNORM)
#define POLLWRBAND  0x0020

#define POLLERR     0x0001
#define POLLHUP     0x0002
#define POLLNVAL    0x0004

typedef struct pollfd {

    SOCKET  fd;
    SHORT   events;
    SHORT   revents;

} WSAPOLLFD, *PWSAPOLLFD, FAR *LPWSAPOLLFD;

typedef int (WSAAPI *njt_wsapoll_pt)(
    LPWSAPOLLFD fdArray,
    ULONG fds,
    INT timeout
    );

extern njt_wsapoll_pt             WSAPoll;
extern njt_uint_t                 njt_have_wsapoll;

#endif


int njt_tcp_push(njt_socket_t s);
#define njt_tcp_push_n            "tcp_push()"


#endif /* _NJT_SOCKET_H_INCLUDED_ */
