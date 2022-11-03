
njt_int_t
ndk_init_signals (njt_signal_t *sig, njt_log_t *log)
{
    struct sigaction   sa;

    for ( ; sig->signo != 0; sig++) {
        ndk_zerov (sa);
        sa.sa_handler = sig->handler;
        sigemptyset (&sa.sa_mask);
        
        if (sigaction (sig->signo, &sa, NULL) == -1) {
            njt_log_error (NJT_LOG_EMERG, log, njt_errno,
                          "sigaction(%s) failed", sig->signame);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}
