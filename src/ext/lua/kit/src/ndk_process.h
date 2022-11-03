

typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo);
} njt_signal_t;


njt_int_t   ndk_init_signals    (njt_signal_t *sig, njt_log_t *log);

