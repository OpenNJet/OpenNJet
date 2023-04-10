
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */



#define NJT_SERVICE_CONTROL_SHUTDOWN   128
#define NJT_SERVICE_CONTROL_REOPEN     129


SERVICE_TABLE_ENTRY st[] = {
    { "njet", service_main },
    { NULL, NULL }
};


njt_int_t
njt_service(njt_log_t *log)
{
    /* primary thread */

    /* StartServiceCtrlDispatcher() should be called within 30 seconds */

    if (StartServiceCtrlDispatcher(st) == 0) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "StartServiceCtrlDispatcher() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
service_main(u_int argc, char **argv)
{
    SERVICE_STATUS         status;
    SERVICE_STATUS_HANDLE  service;

    /* thread spawned by SCM */

    service = RegisterServiceCtrlHandlerEx("njet", service_handler, ctx);
    if (service == INVALID_HANDLE_VALUE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "RegisterServiceCtrlHandlerEx() failed");
        return;
    }

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP
                                |SERVICE_ACCEPT_PARAMCHANGE;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 1;
    status.dwWaitHint = 2000;

    /* SetServiceStatus() should be called within 80 seconds */

    if (SetServiceStatus(service, &status) == 0) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "SetServiceStatus() failed");
        return;
    }

    /* init */

    status.dwCurrentState = SERVICE_RUNNING;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    if (SetServiceStatus(service, &status) == 0) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "SetServiceStatus() failed");
        return;
    }

    /* call master or worker loop */

    /*
     * master should use event notification and look status
     * single should use iocp to get notifications from service handler
     */

}


u_int
service_handler(u_int control, u_int type, void *data, void *ctx)
{
    /* primary thread */

    switch (control) {

    case SERVICE_CONTROL_INTERROGATE:
        status = NJT_IOCP_INTERROGATE;
        break;

    case SERVICE_CONTROL_STOP:
        status = NJT_IOCP_STOP;
        break;

    case SERVICE_CONTROL_PARAMCHANGE:
        status = NJT_IOCP_RECONFIGURE;
        break;

    case NJT_SERVICE_CONTROL_SHUTDOWN:
        status = NJT_IOCP_REOPEN;
        break;

    case NJT_SERVICE_CONTROL_REOPEN:
        status = NJT_IOCP_REOPEN;
        break;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    if (njt_single) {
        if (PostQueuedCompletionStatus(iocp, ... status, ...) == 0) {
            err = njt_errno;
            njt_log_error(NJT_LOG_ALERT, log, err,
                          "PostQueuedCompletionStatus() failed");
            return err;
        }

    } else {
        Event
    }

    return NO_ERROR;
}
