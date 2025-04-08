#include <njt_http.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <njt_mqconf_module.h>
#include "toml.h"

#define TOML_SECTION "copilot"
#define TOML_PROGNAME_FIELD "progName"
#define TOML_STDOUTFILE_FIELD "stdoutFile"
#define TOML_STDERRFILE_FIELD "stderrFile"

static const char *get_toml_field(njt_cycle_t *cycle, const char *toml_file, const char *section, const char *field)
{
    FILE *fp = fopen(toml_file, "r");
    if (!fp) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "Error: cannot open file %s\n", toml_file);
        return NULL;
    }

    // Parse TOML file
    char errbuf[200];
    toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (!conf) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "Error parsing TOML: %s\n", errbuf);
        return NULL;
    }

    // Find the section
    toml_table_t *section_table = toml_table_in(conf, section);
    if (!section_table) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "Error: section [%s] not found\n", section);
        toml_free(conf);
        return NULL;
    }

    // Find the field in the section 
    toml_datum_t value = toml_string_in(section_table, field);
    if (!value.ok) {
        // some fields are optional, it is not an error in parser, caller should do error log if field is mandatory 
        njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "field %s not found in section [%s]\n", field, section);
        toml_free(conf);
        return NULL;
    }

    // Copy the field value
    char *result = strdup(value.u.s);
    toml_free(conf);

    return result;  // Caller must free this memory
}

static char *njt_helper_go_copilot_append_prefix(njt_cycle_t *cycle, char *prefix, const char *name)
{
    char *pname;
    char *p;
    //if name is not absolute path, append njet prefix to it 
    if (name[0] == '/') {
        pname = njt_calloc(njt_strlen(name) + 1, cycle->log);
        if (pname == NULL) {
            return NULL;
        }
        njt_memcpy(pname, name, njt_strlen(name));
    } else {
        pname = njt_calloc(njt_strlen(prefix) + njt_strlen(name) + 1, cycle->log);
        if (pname == NULL) {
            return NULL;
        }
        p = (char *)njt_cpymem(pname, prefix, njt_strlen(prefix));
        njt_cpystrn((u_char *)p, (u_char *)name, strlen(name) + 1);
    }
    return pname;
}

static njt_pid_t njt_helper_go_copilot_start(njt_cycle_t *cycle, char *prefix, char *log_prefix, char *conf_fn)
{
    njt_exec_ctx_t ctx;
    char *exeName = NULL;
    char *stdoutLog = NULL;
    char *stderrLog = NULL;
    const char *progName = NULL;
    const char *stdoutFile = NULL;
    const char *stderrFile = NULL;
    njt_pid_t pid;
    int  fd;
    int  config_ok = 0;
    int    stdout_file_create = 0;
    int    stderr_file_create = 0;

    progName = get_toml_field(cycle, conf_fn, TOML_SECTION, TOML_PROGNAME_FIELD);
    if (progName == NULL || njt_strlen(progName) == 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "Value of %s in section [%s]: not configured", TOML_PROGNAME_FIELD, TOML_SECTION);
        pid = NJT_INVALID_PID;
        goto cleanup;
    } else {
        exeName = njt_helper_go_copilot_append_prefix(cycle, prefix, progName);
    }
    if (exeName == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "can't get progName in njt_helper_go_copilot_start");
        pid = NJT_INVALID_PID;
        goto cleanup;
    }
    stdoutFile = get_toml_field(cycle, conf_fn, TOML_SECTION, TOML_STDOUTFILE_FIELD);
    if (stdoutFile == NULL || njt_strlen(stdoutFile) == 0) {
        //to make the following code simple, copy literal str to dynamic str 
        stdoutLog = njt_helper_go_copilot_append_prefix(cycle, log_prefix, "/dev/null");
    } else {
        stdout_file_create = 1;
        stdoutLog = njt_helper_go_copilot_append_prefix(cycle, log_prefix, stdoutFile);
    }
    if (stdoutLog == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "can't get stdoutFile in njt_helper_go_copilot_start");
        pid = NJT_INVALID_PID;
        goto cleanup;
    }

    stderrFile = get_toml_field(cycle, conf_fn, TOML_SECTION, TOML_STDERRFILE_FIELD);
    if (stderrFile == NULL || njt_strlen(stderrFile) == 0) {
        //to make the following code simple, copy literal str to dynamic str
        stderrLog = njt_helper_go_copilot_append_prefix(cycle, log_prefix, "/dev/null");
    } else {
        stderr_file_create = 1;
        stderrLog = njt_helper_go_copilot_append_prefix(cycle, log_prefix, stderrFile);
    }
    if (stderrLog == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "can't get stderrFile in njt_helper_go_copilot_start");
        pid = NJT_INVALID_PID;
        goto cleanup;
    }
    //open log file and set stdout and stderr 
    if (stdout_file_create) {
        fd = open(stdoutLog, O_RDWR | O_CREAT | O_TRUNC, 0644);
    } else {
        fd = open(stdoutLog, O_RDWR);
    }
    if (fd == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno, "open %s error", stdoutLog);
        pid = NJT_INVALID_PID;
        goto cleanup;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno, "dup2(STDOUT) failed");
        pid = NJT_INVALID_PID;
        goto cleanup;
    }
    if (njt_strncmp(stdoutLog, stderrLog, njt_strlen(stdoutLog) != 0)) {
        if (stderr_file_create) {
            fd = open(stderrLog, O_RDWR | O_CREAT | O_TRUNC, 0644);
        } else {
            fd = open(stderrLog, O_RDWR);
        }

        if (fd == -1) {
            njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno, "open %s error", stderrLog);
            pid = NJT_INVALID_PID;
            goto cleanup;
        }
    }
    if (dup2(fd, STDERR_FILENO) == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno, "dup2(STDERR) failed");
        pid = NJT_INVALID_PID;
        goto cleanup;
    }

    config_ok = 1;
    ctx.path = exeName;
    ctx.name = "go-copilot in njt_execute";
    njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "start go program: '%s %s %s  \n", exeName, "--config.file", conf_fn);
    ctx.argv = (char *const []){ exeName, "-p", prefix, "-c", conf_fn, NULL };
    ctx.envp = (char *const []){ NULL };
    pid = njt_execute(cycle, &ctx);

cleanup:
    if (progName) njt_free((void *)progName);
    if (stdoutFile) njt_free((void *)stdoutFile);
    if (stderrFile) njt_free((void *)stderrFile);
    if (exeName) njt_free(exeName);
    if (stdoutLog) njt_free(stdoutLog);
    if (stderrLog) njt_free(stderrLog);
    if (config_ok != 1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "provided file is not a valid go copliot config, exit and not respawn");
        exit(2);
    }

    return pid;
}

void
njt_helper_run(helper_param param)
{
    int signo;
    njt_err_t err;
    unsigned int cmd;
    char *prefix, *log_prefix, *conf_fn;
    njt_cycle_t *cycle;
    njt_pid_t go_coplilot_pid;

    cycle = param.cycle;

    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_cpystrn((u_char *)prefix, cycle->prefix.data, cycle->prefix.len + 1);

    log_prefix = njt_calloc(cycle->log_prefix.len + 1, cycle->log);
    njt_cpystrn((u_char *)log_prefix, cycle->log_prefix.data, cycle->log_prefix.len + 1);

    conf_fn = njt_calloc(param.conf_fullfn.len + 1, cycle->log);
    njt_cpystrn((u_char *)conf_fn, param.conf_fullfn.data, param.conf_fullfn.len + 1);

    njt_reconfigure = 1;
    go_coplilot_pid = NJT_INVALID_PID;

    for (;; ) {
        if (njt_reconfigure) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go-copilot %V start/reconfiguring", &param.conf_fullfn);
            if (go_coplilot_pid != NJT_INVALID_PID) {
                signo = njt_signal_value(NJT_TERMINATE_SIGNAL);
                if (kill(go_coplilot_pid, signo) == -1) {
                    err = njt_errno;
                    njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                        "kill go-copilot ctrl-o(%P, %d) failed", go_coplilot_pid, signo);
                }
            }

            go_coplilot_pid = njt_helper_go_copilot_start(cycle, prefix, log_prefix, conf_fn);
            if (go_coplilot_pid == NJT_INVALID_PID) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go-copilot %V start/reconfiguring failed", &param.conf_fullfn);
            } else {
                njt_reconfigure = 0;
            }
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go-copilot %V start/reconfiguring done", &param.conf_fullfn);
        }

        cmd = param.check_cmd_fp(cycle);
        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        if (cmd == NJT_HELPER_CMD_STOP) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go-copilot %V exit", &param.conf_fullfn);
            signo = njt_signal_value(NJT_TERMINATE_SIGNAL);
            kill(go_coplilot_pid, signo);
            njt_free(prefix);
            njt_free(log_prefix);
            njt_free(conf_fn);
            break;
        }

        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go-copilot %V restart", &param.conf_fullfn);
            njt_reconfigure = 1;
        }
    }

    return;
}

unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}

njt_module_t njt_helper_go_copilot_module = { 0 };
