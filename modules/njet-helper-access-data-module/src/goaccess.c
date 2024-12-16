/**
 * goaccess.c -- main log analyzer
 *    ______      ___
 *   / ____/___  /   | _____________  __________
 *  / / __/ __ \/ /| |/ ___/ ___/ _ \/ ___/ ___/
 * / /_/ / /_/ / ___ / /__/ /__/  __(__  |__  )
 * \____/\____/_/  |_\___/\___/\___/____/____/
 *
 * The MIT License (MIT)
 * Copyright (c) 2009-2024 Gerardo Orellana <hello @ goaccess.io>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS    64

#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include <locale.h>

#include "config.h"

#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#include "gkhash.h"

#ifdef HAVE_GEOLOCATION
#include "geoip1.h"
#endif

#include "browsers.h"
#include "csv.h"
#include "error.h"
#include "gdashboard.h"
#include "gdns.h"
#include "gholder.h"
#include "goaccess.h"
#include "gwsocket.h"
#include "json.h"
#include "options.h"
#include "output.h"
#include "util.h"
#include "websocket.h"
#include "xmalloc.h"
#include <njt_core.h>

void process_ctrl();
njt_int_t  goaccess_shpool_lock_flag;
static njt_err_t
njt_create_output_file(u_char *dir, njt_uid_t user, njt_uid_t group, njt_uint_t access, njt_cycle_t *cycle);
extern goaccess_shpool_ctx_t  goaccess_shpool_ctx;
GConf conf = {
  .append_method = 1,
  .append_protocol = 1,
  .chunk_size = 1024,
  .hl_header = 1,
  .jobs = 1,
  .num_tests = 10,
  .keep_last = 7,
  .addr = "127.0.0.1",
  .client_err_to_unique_count = 1,
};


/* Loading/Spinner */
GSpinner *parsing_spinner;
/* active reverse dns flag */
int active_gdns = 0;

/* WebSocket server - writer and reader threads */
static GWSWriter *gwswriter;
static GWSReader *gwsreader;
/* Dashboard data structure */
/* Data holder structure */
GHolder *holder;
/* Old signal mask */
static sigset_t oldset;
/* Curses windows */


/* *INDENT-OFF* */
static GScroll gscroll = {
  {
     {0, 0}, /* VISITORS        { scroll, offset} */
     {0, 0}, /* REQUESTS        { scroll, offset} */
     {0, 0}, /* REQUESTS_STATIC { scroll, offset} */
     {0, 0}, /* NOT_FOUND       { scroll, offset} */
     {0, 0}, /* HOSTS           { scroll, offset} */
     {0, 0}, /* OS              { scroll, offset} */
     {0, 0}, /* BROWSERS        { scroll, offset} */
     {0, 0}, /* VISIT_TIMES     { scroll, offset} */
     {0, 0}, /* VIRTUAL_HOSTS   { scroll, offset} */
     {0, 0}, /* REFERRERS       { scroll, offset} */
     {0, 0}, /* REFERRING_SITES { scroll, offset} */
     {0, 0}, /* KEYPHRASES      { scroll, offset} */
     {0, 0}, /* STATUS_CODES    { scroll, offset} */
     {0, 0}, /* REMOTE_USER     { scroll, offset} */
     {0, 0}, /* CACHE_STATUS    { scroll, offset} */
#ifdef HAVE_GEOLOCATION
     {0, 0}, /* GEO_LOCATION    { scroll, offset} */
     {0, 0}, /* ASN             { scroll, offset} */
#endif
     {0, 0}, /* MIME_TYPE       { scroll, offset} */
     {0, 0}, /* TLS_TYPE        { scroll, offset} */
  },
  0,         /* current module */
  0,         /* main dashboard scroll */
  0,         /* expanded flag */
};
/* *INDENT-ON* */



void
cleanup (int ret) {
  if (conf.persist && goaccess_shpool_ctx.shpool != NULL)
  {
    if (goaccess_shpool_ctx.shpool)
    {
      njt_rwlock_wlock(goaccess_shpool_ctx.rwlock);
      goaccess_shpool_lock_flag = 1;
    }
    persist_data();
    if (goaccess_shpool_ctx.shpool)
    {
      njt_rwlock_unlock(goaccess_shpool_ctx.rwlock);
      goaccess_shpool_lock_flag = 0;
    }
  }
  return; //zyg 
}

/* Drop permissions to the user specified. */
static void
drop_permissions (void) {
  struct passwd *pw;

  errno = 0;
  if ((pw = getpwnam (conf.username)) == NULL) {
    if (errno == 0)
      FATAL ("No such user %s", conf.username);
    FATAL ("Unable to retrieve user %s: %s", conf.username, strerror (errno));
  }

  if (setgroups (1, &pw->pw_gid) == -1)
    FATAL ("setgroups: %s", strerror (errno));
  if (setgid (pw->pw_gid) == -1)
    FATAL ("setgid: %s", strerror (errno));
  if (setuid (pw->pw_uid) == -1)
    FATAL ("setuid: %s", strerror (errno));
}

/* Open the pidfile whose name is specified in the given path and write
 * the daemonized given pid. */
static void
write_pid_file (const char *path, pid_t pid) {
  FILE *pidfile;

  if (!path)
    return;

  if ((pidfile = fopen (path, "w"))) {
    fprintf (pidfile, "%d", pid);
    fclose (pidfile);
  } else {
    FATAL ("Unable to open the specified pid file. %s", strerror (errno));
  }
}

/* Set GoAccess to run as a daemon */
static void
daemonize (void) {
  pid_t pid, sid;
  int fd;

  /* Clone ourselves to make a child */
  pid = fork ();

  if (pid < 0)
    exit (EXIT_FAILURE);
  if (pid > 0) {
    write_pid_file (conf.pidfile, pid);
    printf ("Daemonized GoAccess: %d\n", pid);
    exit (EXIT_SUCCESS);
  }

  umask (0);
  /* attempt to create our own process group */
  sid = setsid ();
  if (sid < 0) {
    LOG_DEBUG (("Unable to setsid: %s.\n", strerror (errno)));
    exit (EXIT_FAILURE);
  }

  /* set the working directory to the root directory.
   * requires the user to specify absolute paths */
  if (chdir ("/") < 0) {
    LOG_DEBUG (("Unable to set chdir: %s.\n", strerror (errno)));
    exit (EXIT_FAILURE);
  }

  /* redirect fd's 0,1,2 to /dev/null */
  /* Note that the user will need to use --debug-file for log output */
  if ((fd = open ("/dev/null", O_RDWR, 0)) == -1) {
    LOG_DEBUG (("Unable to open /dev/null: %s.\n", strerror (errno)));
    exit (EXIT_FAILURE);
  }

  dup2 (fd, STDIN_FILENO);
  dup2 (fd, STDOUT_FILENO);
  dup2 (fd, STDERR_FILENO);
  if (fd > STDERR_FILENO) {
    close (fd);
  }
}

/* Extract data from the given module hash structure and allocate +
 * load data from the hash table into an instance of GHolder */
static void
allocate_holder_by_module (GModule module,int use_pool) {
  GRawData *raw_data;

  /* extract data from the corresponding hash table */
  raw_data = parse_raw_data (module);
  if (!raw_data) {
    LOG_DEBUG (("raw data is NULL for module: %d.\n", module));
    return;
  }

  load_holder_data (raw_data, holder + module, module, module_sort[module]);
}

/* Iterate over all modules/panels and extract data from hash
 * structures and load it into an instance of GHolder */
void
allocate_holder (void) {
  size_t idx = 0;

  holder = new_gholder (TOTAL_MODULES);
  FOREACH_MODULE (idx, module_list) {
    allocate_holder_by_module (module_list[idx],0);
  }
}

void
njt_allocate_holder (void) {
  size_t idx = 0;

  holder = njt_new_gholder (TOTAL_MODULES);
  FOREACH_MODULE (idx, module_list) {
    allocate_holder_by_module (module_list[idx],1);
  }
}






void
tail_html (void) {
  //LOG_DEBUG (("===========1=====tail_html gwswriter->fd:%d \n", gwswriter->fd));
  char *json = NULL;

  pthread_mutex_lock (&gdns_thread.mutex);
  pthread_cond_broadcast (&gdns_thread.not_empty);
  pthread_mutex_unlock (&gdns_thread.mutex);

  allocate_holder ();

  pthread_mutex_lock (&gdns_thread.mutex);


  json = get_json (holder, 1);


  pthread_mutex_unlock (&gdns_thread.mutex);

  if (json == NULL) {
    return;
  }
  if (conf.real_time_html) {
  pthread_mutex_lock (&gwswriter->mutex);
  broadcast_holder (gwswriter->fd, json, strlen (json));
  pthread_mutex_unlock (&gwswriter->mutex);
  }
  free (json);
}

/* Fast-forward latest JSON data when client connection is opened. */
static void
fast_forward_client (int listener) {
  char *json = NULL;

  pthread_mutex_lock (&gdns_thread.mutex);
  json = get_json (holder, 1);
  pthread_mutex_unlock (&gdns_thread.mutex);

  if (json == NULL)
    return;

  pthread_mutex_lock (&gwswriter->mutex);
  send_holder_to_client (gwswriter->fd, listener, json, strlen (json));
  pthread_mutex_unlock (&gwswriter->mutex);
  free (json);
}

/* Start reading data coming from the client side through the
 * WebSocket server. */
void
read_client (void *ptr_data) {
  GWSReader *reader = (GWSReader *) ptr_data;

  /* check we have a fifo for reading */
  if (reader->fd == -1)
    return;

  pthread_mutex_lock (&reader->mutex);
  set_self_pipe (reader->self_pipe);
  pthread_mutex_unlock (&reader->mutex);

  while (1) {
    /* poll(2) will block */
    if (read_fifo (reader, fast_forward_client))
      break;
  }
  close (reader->fd);
}




/* Loop over and perform a follow for the given logs */
void tail_loop_output(Logs *logs)
{
  njt_err_t err;
  njt_int_t ret;
  njt_str_t   fhtml;
  njt_str_t   fjson;
  njt_str_t   fcsv;
  struct timespec refresh = {
      .tv_sec = conf.html_refresh ? conf.html_refresh : HTML_REFRESH,
      .tv_nsec = 0,
  };

  long num = 0;
  char *csv = NULL, *json = NULL, *html = NULL;
  njt_core_conf_t  *ccf;
  njt_file_info_t   fi;

  
	ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                                   njt_core_module);
  find_output_type(&html, "html", 1);
  find_output_type(&json, "json", 1);
  find_output_type(&csv, "csv", 1);
  free_holder(&holder);

  if (html)
  {
    fhtml.data = (u_char *)html;
    fhtml.len = njt_strlen(html);
    if (njt_conf_full_name((njt_cycle_t *)njt_cycle, &fhtml, 1) != NJT_OK)
    {
      free(html);
      html = NULL;
    }
  }
  if (json)
  {
    fjson.data = (u_char *)json;
    fjson.len = njt_strlen(json);
    if (njt_conf_full_name((njt_cycle_t *)njt_cycle, &fjson, 1) != NJT_OK)
    {
      free(json);
      json = NULL;
    }
  }
  if (csv)
  {
    fcsv.data = (u_char *)csv;
    fcsv.len = njt_strlen(csv);
    if (njt_conf_full_name((njt_cycle_t *)njt_cycle, &fcsv, 1) != NJT_OK)
    {
      free(csv);
      csv = NULL;
    }
  }
  if(ccf && html) {
    err = 0;
    ret = njt_file_info(fhtml.data, &fi);
    if(ret == NJT_FILE_ERROR) {
      njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,"create file=%V",&fhtml);
      err = njt_create_output_file((u_char *)fhtml.data,ccf->user,ccf->group,0755,(njt_cycle_t *)njt_cycle);
    }
    if(err != 0) {
      free(html);
      html = NULL;
    }
  }
   if(ccf && json) {
    err = 0;
    ret = njt_file_info(fjson.data, &fi);
    if(ret == NJT_FILE_ERROR) {
      njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,"create file=%V",&fjson);
      err = njt_create_output_file((u_char *)fjson.data,ccf->user,ccf->group,0755,(njt_cycle_t *)njt_cycle);
    }
    if(err != 0) {
      free(json);
      json = NULL;
    }
  }
   if(ccf && csv) {
    err = 0;
    ret = njt_file_info(fcsv.data, &fi);
    if(ret == NJT_FILE_ERROR) {
      njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,"create file=%V",&fcsv);
      err = njt_create_output_file((u_char *)fcsv.data,ccf->user,ccf->group,0755,(njt_cycle_t *)njt_cycle);
    }
    if(err != 0) {
      free(csv);
      csv = NULL;
    }
  }

  holder = NULL;
  njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,"tail_loop_output");
  while (1)
  {
    num = __sync_fetch_and_add(&logs->glog->processed, 0);
    if (num >= 0 && (html  || csv || json)) // 没数据，等于0，也刷新。
    {
      if (goaccess_shpool_ctx.shpool)
      {
        njt_rwlock_wlock(goaccess_shpool_ctx.rwlock);
        goaccess_shpool_lock_flag = 1;
      }
      if (html != NULL)
      {
        if (holder == NULL)
        {
          tail_html();
        }
        if (holder != NULL)
        {
          output_html(holder, html);
        }
      }
      if (csv != NULL)
      {
        if (holder == NULL)
        {
          tail_html();
        }
        if (holder != NULL)
        {
          output_csv(holder, csv);
        }
      }
      if (json != NULL)
      {
        if (holder == NULL)
        {
          tail_html();
        }
        if (holder != NULL)
        {
          output_json(holder, json);
        }
      }
      if (goaccess_shpool_ctx.shpool)
      {
        njt_rwlock_unlock(goaccess_shpool_ctx.rwlock);
        goaccess_shpool_lock_flag = 0;
      }
    }
    if (holder != NULL)
    {
      free_holder(&holder);
      holder = NULL;
    }
    process_ctrl();
    if (nanosleep(&refresh, NULL) == -1 && errno != EINTR)
      FATAL("nanosleep: %s", strerror(errno));
  }
}

/* Entry point to start processing the HTML output */
static void
process_output (Logs *logs, const char *filename) {
  if (logs->load_from_disk_only)
    return;
 if (conf.real_time_html) {
    pthread_mutex_lock (&gwswriter->mutex);
    gwswriter->fd = open_fifoin ();
    pthread_mutex_unlock (&gwswriter->mutex);

    /* open fifo for write */
    if (gwswriter->fd == -1)
      return;
 }

  set_ready_state ();
  tail_loop_output (logs);
  if (conf.real_time_html) {
    close (gwswriter->fd);
  }
}


/* Store accumulated processing time
 * Note: As we store with time_t second resolution,
 * if elapsed time == 0, we will bump it to 1.
 */
static void
set_accumulated_time (void) {
  time_t elapsed = end_proc - start_proc;
  elapsed = (!elapsed) ? !elapsed : elapsed;
  ht_inc_cnt_overall ("processing_time", elapsed);
}

/* Execute the following calls right before we start the main
 * processing/parsing loop */
static void
init_processing (void) {
  #if 1
  /* perform some additional checks before parsing panels */
  //verify_panels ();  都显示。
  /* initialize storage */
  pthread_mutex_lock (&parsing_spinner->mutex);
  parsing_spinner->label = "SETTING UP STORAGE";
  pthread_mutex_unlock (&parsing_spinner->mutex);
  //init_storage ();
  set_spec_date_format ();

  if ((!conf.skip_term_resolver && !conf.output_stdout) ||
      (conf.enable_html_resolver && conf.real_time_html))
    gdns_thread_create ();

  #endif
}

/* Determine the type of output, i.e., JSON, CSV, HTML */
void
standard_output (Logs *logs) {
   if (conf.real_time_html)
      setup_ws_server (gwswriter, gwsreader);

  process_output (logs, NULL);
}



/* Set locale */
static void
set_locale (void) {
  char *loc_ctype;

  setlocale (LC_ALL, "");
#ifdef ENABLE_NLS
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  bindtextdomain ("goaccess", "/root/njet_main-20240513/njet_main/modules/njet-helper-access-data-module/src/po");
  textdomain ("goaccess");

  loc_ctype = getenv ("LC_CTYPE");
  if (loc_ctype != NULL)
    setlocale (LC_CTYPE, loc_ctype);
  else if ((loc_ctype = getenv ("LC_ALL")))
    setlocale (LC_CTYPE, loc_ctype);
  else
    setlocale (LC_CTYPE, "");
}

/* Attempt to get the current name of a terminal or fallback to /dev/tty
 *
 * On error, -1 is returned
 * On success, the new file descriptor is returned */
static int
open_term (char **buf) {
  const char *term = "/dev/tty";

  if (!isatty (STDERR_FILENO) || (term = ttyname (STDERR_FILENO)) == 0) {
    if (!isatty (STDOUT_FILENO) || (term = ttyname (STDOUT_FILENO)) == 0) {
      if (!isatty (STDIN_FILENO) || (term = ttyname (STDIN_FILENO)) == 0) {
        term = "/dev/tty";
      }
    }
  }
  *buf = xstrdup (term);

  return open (term, O_RDONLY);
}

/* Determine if reading from a pipe, and duplicate file descriptors so
 * it doesn't get in the way of curses' normal reading stdin for
 * wgetch() */
static FILE *
set_pipe_stdin (void) {
  char *term = NULL;
  FILE *pipe = stdin;
  int term_fd = -1;
  int pipe_fd = -1;

  /* If unable to open a terminal, yet data is being piped, then it's
   * probably from the cron, or when running as a user that can't open a
   * terminal. In that case it's still important to set the pipe as
   * non-blocking.
   *
   * Note: If used from the cron, it will require the
   * user to use a single dash to parse piped data such as:
   * cat access.log | goaccess - */
  if ((term_fd = open_term (&term)) == -1)
    goto out1;

  if ((pipe_fd = dup (fileno (stdin))) == -1)
    FATAL ("Unable to dup stdin: %s", strerror (errno));

  pipe = fdopen (pipe_fd, "r");
  if (freopen (term, "r", stdin) == 0)
    FATAL ("Unable to open input from TTY");
  if (fileno (stdin) != 0)
    (void) dup2 (fileno (stdin), 0);

  add_dash_filename ();

out1:

  /* no need to set it as non-blocking since we are simply outputting a
   * static report */
  if (conf.output_stdout && !conf.real_time_html)
    goto out2;

  /* Using select(), poll(), or epoll(), etc may be a better choice... */
  if (pipe_fd == -1)
    pipe_fd = fileno (pipe);
  if (fcntl (pipe_fd, F_SETFL, fcntl (pipe_fd, F_GETFL, 0) | O_NONBLOCK) == -1)
    FATAL ("Unable to set fd as non-blocking: %s.", strerror (errno));

out2:

  free (term);

  return pipe;
}

/* Determine if we are getting data from the stdin, and where are we
 * outputting to. */
static void
set_io (FILE **pipe) {
  /* For backwards compatibility, check if we are not outputting to a
   * terminal or if an output format was supplied */
  if (!isatty (STDOUT_FILENO) || conf.output_format_idx > 0)
    conf.output_stdout = 1;
  /* dup fd if data piped */
  if (!isatty (STDIN_FILENO))
    *pipe = set_pipe_stdin ();
}

/* Process command line options and set some default options. */
static void
parse_cmd_line (int argc, char **argv) {
  read_option_args (argc, argv);
  set_default_static_files ();
}

static void
handle_signal_action (GO_UNUSED int sig_number) {
  if (sig_number == SIGINT)
    njet_helper_access_log(NJT_LOG_NOTICE, "SIGINT caught!");
  else if (sig_number == SIGTERM)
    njet_helper_access_log(NJT_LOG_NOTICE, "SIGTERM caught!");
  else if (sig_number == SIGQUIT)
    njet_helper_access_log(NJT_LOG_NOTICE, "SIGQUIT caught!");
  else
    njet_helper_access_log(NJT_LOG_NOTICE, "Signal %d caught!", sig_number);
  njet_helper_access_log(NJT_LOG_NOTICE, "Closing GoAccess...");

  if (conf.output_stdout && conf.real_time_html)
    stop_ws_server (gwswriter, gwsreader);
  conf.stop_processing = 1;
}

static void
setup_thread_signals (void) {
  struct sigaction act;

  act.sa_handler = handle_signal_action;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;

  sigaction (SIGINT, &act, NULL);
  sigaction (SIGTERM, &act, NULL);
  sigaction (SIGQUIT, &act, NULL);
  signal (SIGPIPE, SIG_IGN);

  /* Restore old signal mask for the main thread */
  pthread_sigmask (SIG_SETMASK, &oldset, NULL);
}

#if 1
static void
block_thread_signals (void) {
  /* Avoid threads catching SIGINT/SIGPIPE/SIGTERM/SIGQUIT and handle them in
   * main thread */
  sigset_t sigset;
  sigemptyset (&sigset);
  sigaddset (&sigset, SIGINT);
  sigaddset (&sigset, SIGPIPE);
  sigaddset (&sigset, SIGTERM);
  sigaddset (&sigset, SIGQUIT);
  pthread_sigmask (SIG_BLOCK, &sigset, &oldset);
}
#endif

/* Initialize various types of data. */
static Logs *
initializer (void) {
  int i;
  FILE *pipe = NULL;
  Logs *logs;

  /* drop permissions right away */
  if (conf.username)
    drop_permissions ();

  /* then initialize modules and set */
  gscroll.current = init_modules ();
  /* setup to use the current locale */
  set_locale ();

  parse_browsers_file ();

#ifdef HAVE_GEOLOCATION
  init_geoip ();
#endif

  set_io (&pipe);
  if (!(logs = init_logs (conf.filenames_idx)))
    FATAL (ERR_NO_DATA_PASSED);

  set_signal_data (logs);

  for (i = 0; i < logs->size; ++i)
    if (logs->glog[i].props.filename[0] == '-' && logs->glog[i].props.filename[1] == '\0')
      logs->glog[i].pipe = pipe;

  /* init parsing spinner */
  parsing_spinner = new_gspinner ();
  parsing_spinner->processed = &(logs->processed);
  parsing_spinner->filename = &(logs->filename);

  /* init reverse lookup thread */
  gdns_init ();

  /* init random number generator */
  srand (getpid ());
  //init_pre_storage (logs);

  return logs;
}

static char *
generate_fifo_name (void) {
  char fname[RAND_FN];
  const char *tmp;
  char *path;
  size_t len;

  if ((tmp = getenv ("TMPDIR")) == NULL)
    tmp = "/tmp";

  memset (fname, 0, sizeof (fname));
  genstr (fname, RAND_FN - 1);

  len = snprintf (NULL, 0, "%s/goaccess_fifo_%s", tmp, fname) + 1;
  path = xmalloc (len);
  snprintf (path, len, "%s/goaccess_fifo_%s", tmp, fname);

  return path;
}

static int
spawn_ws (void) {
  gwswriter = new_gwswriter ();
  gwsreader = new_gwsreader ();

  if (!conf.fifo_in)
    conf.fifo_in = generate_fifo_name ();
  if (!conf.fifo_out)
    conf.fifo_out = generate_fifo_name ();

  /* open fifo for read */
  if ((gwsreader->fd = open_fifoout ()) == -1) {
    LOG (("Unable to open FIFO for read.\n"));
    return 1;
  }

  if (conf.daemonize)
    daemonize ();

  return 0;
}

static void
set_standard_output (void) {
  int html = 0;

  /* HTML */
  if (find_output_type (NULL, "html", 0) == 0 || conf.output_format_idx == 0)
    html = 1;

  /* Spawn WebSocket server threads */
  if (html && conf.real_time_html) {
    if (spawn_ws ())
      return;
  }
  setup_thread_signals ();

  /* Spawn progress spinner thread */
  ui_spinner_create (parsing_spinner);
}

/* Set up curses. */
static void
set_curses (Logs *logs, int *quit) {
  
}
njt_int_t set_db_realpath(char *path) { //conf.db_path
  conf.db_path = path;
  return NJT_OK;
}
/* Where all begins... */
//int njet_helper_access_data_init (int argc, char **argv) {
Logs *
njet_helper_access_data_init (int argc, char **argv) {

  Logs *logs = NULL;

  block_thread_signals ();
  setup_sigsegv_handler ();

  /* command line/config options */
  verify_global_config (argc, argv);
  parse_conf_file (&argc, &argv);
  parse_cmd_line (argc, argv);
  set_db_realpath(goaccess_shpool_ctx.db_path);
  
  
  logs = initializer ();

  return logs;
}

void *
njet_helper_access_data_run (void *log_s) {

  int quit = 0, ret = 0;
  Logs *logs = (Logs *)log_s;
  if (logs == NULL) {
    return 0;
  }

  /* ignore outputting, process only */
  if (conf.process_and_exit) {
  }
  /* set stdout */
  else if (conf.output_stdout) {
    set_standard_output ();
  }
  /* set curses */
  else {
    set_curses (logs, &quit);
  }

  /* no log/date/time format set */
  if (quit)
    goto clean;

  init_processing ();

  /* main processing event */
  time (&start_proc);
  parsing_spinner->label = "PARSING";

  if (conf.stop_processing)
    goto clean;

  pthread_mutex_lock (&parsing_spinner->mutex);
  parsing_spinner->label = "RENDERING";
  pthread_mutex_unlock (&parsing_spinner->mutex);

  parse_initial_sort ();
   njt_log_debug(NJT_LOG_DEBUG, njt_cycle->log, 0,"allocate_holder");
  allocate_holder ();

  end_spinner ();
  time (&end_proc);

  njt_log_debug(NJT_LOG_DEBUG, njt_cycle->log, 0,"set_accumulated_time");
  set_accumulated_time ();
  if (conf.process_and_exit) {
  }
  /* stdout */
  else if (conf.output_stdout) {
    njt_log_debug(NJT_LOG_DEBUG, njt_cycle->log, 0,"standard_output");
    standard_output (logs);
  }
  

  return NULL;

  /* clean */
clean:
  cleanup (ret);

  return NULL;

}

static njt_err_t
njt_create_output_file(u_char *dir, njt_uid_t user, njt_uid_t group, njt_uint_t access, njt_cycle_t *cycle)
{
  u_char *p, ch;
  njt_err_t err;
  njt_fd_t fd;
  
  err = 0;

#if (NJT_WIN32)
  p = dir + 3;
#else
  p = dir + 1;
#endif

  for (/* void */; *p; p++)
  {
    ch = *p;

    if (ch != '/')
    {
      continue;
    }

    *p = '\0';

    if (njt_create_dir(dir, access) == NJT_FILE_ERROR)
    {
      err = njt_errno;

      switch (err)
      {
      case NJT_EEXIST:
        err = NJT_EEXIST;
        break;
      case NJT_EACCES:
        break;

      default:
        return err;
      }
    }
    if (err == 0)
    {
      if (chown((const char *)dir, user, getgid()) == -1)
      {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "chmod() \"%s\" failed", dir);
      }
    }
    err = 0;
    *p = '/';
  }
  fd = njt_open_file(dir, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_OPEN, 0666);
  if (fd == NJT_INVALID_FILE)
  {
    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                  "njt_open_file() \"%s\" failed", dir);
    err = njt_errno;
    return err;
  }
  if (fchown(fd, user, group) == -1)
  {
    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                  "fchown() \"%s\" failed", dir);
  }
  if (njt_close_file(fd) == NJT_FILE_ERROR)
  {
    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                  "njt_close_file() \"%s\" failed", dir);
  }

  return err;
}
void njet_helper_access_log(int level, const char *fmt, ...){
  u_char buf[NJT_MAX_ERROR_STR] = {0};
    va_list args;
    u_char *p;
    njt_str_t msg;

    va_start(args, fmt);
    p = njt_vslprintf(buf, buf + NJT_MAX_ERROR_STR, fmt, args);
    va_end(args);

    msg.data = buf;
    msg.len = p - buf;

    njt_log_error((njt_uint_t)level, njt_cycle->log, 0, "%V", &msg);
}
void njet_helper_access_fatal_error()
{
    if (goaccess_shpool_ctx.shpool && goaccess_shpool_lock_flag == 1)
    {
      njt_rwlock_unlock(goaccess_shpool_ctx.rwlock);
      goaccess_shpool_lock_flag = 0;
    }
}