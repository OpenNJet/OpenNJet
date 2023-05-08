/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "vrrp_emb.h"
#include "vrrp_daemon.h"
#include "main.h"
#include "logger.h"
#include "global_data.h"
#include "global_parser.h"
#include "vrrp_parser.h"
#include "parser.h"
#include "track_file.h"
#include "reload_monitor.h"


extern int start_vrrp_child2(void);
extern void vrrp_add_stop_event(void);

static char *override_namespace;

bool reload;  
const char *conf_file;	
bool use_pid_dir;
unsigned child_wait_time;
bool umask_cmdline;
pid_t vrrp_child;
const char * main_pidfile;
const char * vrrp_pidfile;
unsigned num_reloading;
unsigned long daemon_mode;

static const vector_t * global_init_keywords(void)
{
    init_global_keywords(true);
    init_vrrp_keywords(false);
    add_track_file_keywords(false);
    return keywords;
}
static void
read_config_file(bool write_config_copy)
{
    //if (write_config_copy)
        //create_reload_file();
    init_data(conf_file, global_init_keywords, write_config_copy);
    //if (write_config_copy)
        //remove_reload_file();
}
static bool reload_config(void)
{
    bool unsupported_change = false;
    log_message(LOG_INFO, "Reloading ...");
    //if (global_data->reload_time_file)
        //stop_reload_monitor();
    /* Clear any config errors from previous loads */
    clear_config_status();
    /* Make sure there isn't an attempt to change the network namespace or instance name */
    old_global_data = global_data;
    global_data = NULL;
    global_data = alloc_global_data();
	
	//read_config_file(!old_global_data->reload_check_config);

    init_global_data(global_data, old_global_data, false);

    if (override_namespace) {
        FREE_CONST_PTR(global_data->network_namespace);
        global_data->network_namespace = STRDUP(override_namespace);
    }

    if (!!old_global_data->network_namespace != !!global_data->network_namespace ||
        (global_data->network_namespace && strcmp(old_global_data->network_namespace, global_data->network_namespace))) {
        log_message(LOG_INFO, "Cannot change network namespace at a reload - please restart %s", PACKAGE);
        unsupported_change = true;
    }
 if (!!old_global_data->instance_name != !!global_data->instance_name ||
        (global_data->instance_name && strcmp(old_global_data->instance_name, global_data->instance_name))) {
        log_message(LOG_INFO, "Cannot change instance name at a reload - please restart %s", PACKAGE);
        unsupported_change = true;
    }

#ifdef _WITH_NFTABLES_
#ifdef _WITH_VRRP_
    if (!!old_global_data->vrrp_nf_table_name != !!global_data->vrrp_nf_table_name ||
        (global_data->vrrp_nf_table_name && strcmp(old_global_data->vrrp_nf_table_name, global_data->vrrp_nf_table_name))) {
        log_message(LOG_INFO, "Cannot change nftables table name at a reload - please restart %s", PACKAGE);
        unsupported_change = true;
    }
#endif
#endif
if (!!old_global_data->config_directory != !!global_data->config_directory ||
        (global_data->config_directory && strcmp(old_global_data->config_directory, global_data->config_directory))) {
        log_message(LOG_INFO, "Cannot change config_directory at a reload - please restart %s", PACKAGE);
        unsupported_change = true;
    }

#ifdef _WITH_VRRP_
    if (old_global_data->disable_local_igmp != global_data->disable_local_igmp) {
        log_message(LOG_INFO, "Cannot change disable_local_igmp at a reload - please restart %s", PACKAGE);
        unsupported_change = true;
    }
#endif

    if (unsupported_change) {
        /* We cannot reload the configuration, so continue with the old config */
        free_global_data (global_data);
        global_data = old_global_data;
    }
 else {
        /* Update process name if necessary */
        if (!global_data->process_name != !old_global_data->process_name ||
            (global_data->process_name && strcmp(global_data->process_name, old_global_data->process_name)))
            //set_process_name(global_data->process_name);

        free_global_data (old_global_data);
    }
if (global_data->reload_time_file)
       start_reload_monitor();

    return !unsupported_change;

	
}
static void
do_reload(void)
{

    if (!reload_config())
        return;
    //propagate_signal(NULL, SIGHUP);
    if (vrrp_child > 0)
        num_reloading++;
}

void
start_reload(thread_ref_t thread)
{

    if (!global_data->reload_check_config) {
        do_reload();
        return;
    }
    //start_validate_reload_conf_child();
}


int vrrp_emb_init(const char* cfg,const char* log)
{
	conf_file=cfg;
	prog_type = PROG_TYPE_PARENT;
	set_time_now();
	if (!check_conf_file(conf_file)) {
		return -1;
	}
	global_data = alloc_global_data();
	init_data(conf_file, global_init_keywords, true);

    if (had_config_file_error()) {
		return -2;
    }
	log_file_name = log;

    /* Clear any child finder functions set in parent */
    set_child_finder_name(NULL);

    /* Create an independant file descriptor for the shared config file */
    separate_config_file();
	/*	leave master creation in vrrp
	if (master) thread_destroy_master(master);  // This destroys any residual settings from the parent 
    master = thread_make_master();
	if (!master) return -4;
	*/
    /* Register emergency shutdown function */
	__set_bit(DAEMON_VRRP, &daemon_mode);
	
	return 0;
}
void vrrp_emb_run(void){
	start_vrrp_child2();
	//launch_thread_scheduler(master);
}
void vrrp_emb_stop(void){
	vrrp_add_stop_event();
}
