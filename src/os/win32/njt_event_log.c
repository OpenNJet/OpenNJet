/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#define NJT_MAX_ERROR_STR   2048


void njt_cdecl
njt_event_log(njt_err_t err, const char *fmt, ...)
{
    u_char         *p, *last;
    long            types;
    HKEY            key;
    HANDLE          ev;
    va_list         args;
    u_char          text[NJT_MAX_ERROR_STR];
    const char     *msgarg[9];
    static u_char   netmsg[] = "%SystemRoot%\\System32\\netmsg.dll";

    last = text + NJT_MAX_ERROR_STR;
    p = text + GetModuleFileName(NULL, (char *) text, NJT_MAX_ERROR_STR - 50);

    *p++ = ':';
    njt_linefeed(p);

    va_start(args, fmt);
    p = njt_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = njt_log_errno(p, last, err);
    }

    if (p > last - NJT_LINEFEED_SIZE - 1) {
        p = last - NJT_LINEFEED_SIZE - 1;
    }

    njt_linefeed(p);

    *p = '\0';

    /*
     * we do not log errors here since we use
     * Event Log only to log our own logs open errors
     */

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
           "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\njet",
           0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL)
        != 0)
    {
        return;
    }

    if (RegSetValueEx(key, "EventMessageFile", 0, REG_EXPAND_SZ,
                      netmsg, sizeof(netmsg) - 1)
        != 0)
    {
        return;
    }

    types = EVENTLOG_ERROR_TYPE;

    if (RegSetValueEx(key, "TypesSupported", 0, REG_DWORD,
                      (u_char *) &types, sizeof(long))
        != 0)
    {
        return;
    }

    RegCloseKey(key);

    ev = RegisterEventSource(NULL, "njet");

    msgarg[0] = (char *) text;
    msgarg[1] = NULL;
    msgarg[2] = NULL;
    msgarg[3] = NULL;
    msgarg[4] = NULL;
    msgarg[5] = NULL;
    msgarg[6] = NULL;
    msgarg[7] = NULL;
    msgarg[8] = NULL;

    /*
     * the 3299 event id in netmsg.dll has the generic message format:
     *     "%1 %2 %3 %4 %5 %6 %7 %8 %9"
     */

    ReportEvent(ev, EVENTLOG_ERROR_TYPE, 0, 3299, NULL, 9, 0, msgarg, NULL);

    DeregisterEventSource(ev);
}
