/**
 * ui.c -- various curses interfaces
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
#define _FILE_OFFSET_BITS 64

#define STDIN_FILENO  0
#ifndef _BSD_SOURCE
#define _BSD_SOURCE     /* include stuff from 4.3 BSD */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "config.h"

#include <pthread.h>
#include <ctype.h>

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ui.h"

#include "color.h"
#include "error.h"
#include "gkhash.h"
#include "gmenu.h"
#include "goaccess.h"
#include "util.h"
#include "xmalloc.h"

/* *INDENT-OFF* */
/* Determine which metrics should be displayed per module/panel */
static GOutput outputting[] = {
  {VISITORS        , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 1 , 1} ,
  {REQUESTS        , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0} ,
  {REQUESTS_STATIC , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0} ,
  {NOT_FOUND       , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0} ,
  {HOSTS           , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 1 , 0} ,
  {OS              , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 1 , 1} ,
  {BROWSERS        , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 1 , 1} ,
  {VISIT_TIMES     , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 1 , 1} ,
  {VIRTUAL_HOSTS   , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {REFERRERS       , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {REFERRING_SITES , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {KEYPHRASES      , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {STATUS_CODES    , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {REMOTE_USER     , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {CACHE_STATUS    , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
#ifdef HAVE_GEOLOCATION
  {GEO_LOCATION    , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {ASN             , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
#endif
  {MIME_TYPE       , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
  {TLS_TYPE        , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 0 , 0} ,
};
/* *INDENT-ON* */

/* Structure to display overall statistics */
typedef struct Field_ {
  const char *field;
  /* char due to log, bw, log_file */
  char *value;
  GColors *(*colorlbl) (void);
  GColors *(*colorval) (void);
  short oneliner;
} Field;

/* Determine which metrics to output given a module
 *
 * On error, or if not found, NULL is returned.
 * On success, the panel value is returned. */
GOutput *
output_lookup (GModule module) {
  int i, num_panels = ARRAY_SIZE (outputting);

  for (i = 0; i < num_panels; i++) {
    if (outputting[i].module == module)
      return &outputting[i];
  }
  return NULL;
}

/* Initialize curses colors */
void
init_colors (int force) {
  /* use default foreground/background colors */
  /* first set a default normal color */
  set_normal_color ();
  /* then parse custom colors and initialize them */
  set_colors (force);
}

/* Ncurses' window handling */
void
set_input_opts (void) {
  //initscr ();
  //clear ();
 // noecho ();
  //halfdelay (10);
  //nonl ();
 // intrflush (stdscr, FALSE);
  //keypad (stdscr, TRUE);

}



/* Get the current calendar time as a value of type time_t and convert
 * time_t to tm as local time */
void
generate_time (void) {
  if (conf.tz_name)
    set_tz ();
  timestamp = time (NULL);
  localtime_r (&timestamp, &now_tm);
}

/* Set the loading spinner as ended and manage the mutex locking. */
void
end_spinner (void) {
  if (conf.no_parsing_spinner)
    return;

  pthread_mutex_lock (&parsing_spinner->mutex);
  parsing_spinner->state = SPN_END;
  pthread_mutex_unlock (&parsing_spinner->mutex);
  if (!parsing_spinner->curses) {
    /* wait for the ui_spinner thread to finish */
    struct timespec ts = {.tv_sec = 0,.tv_nsec = SPIN_UPDATE_INTERVAL };
    if (nanosleep (&ts, NULL) == -1 && errno != EINTR)
      FATAL ("nanosleep: %s", strerror (errno));
  }
}




#pragma GCC diagnostic ignored "-Wformat-nonliteral"
/* Draw a generic header with the ability to set a custom text to it. */
void
draw_header (void *win, const char *s, const char *fmt, int y, int x, int w,
             GColors *(*func) (void)) {
  //GColors *color = (*func) ();
  char *buf;

  buf = xmalloc (snprintf (NULL, 0, fmt, s) + 1);
  sprintf (buf, fmt, s);

  //wattron (win, color->attr | COLOR_PAIR (color->pair->idx));
  //mvwhline (win, y, x, ' ', w);
  //mvwaddnstr (win, y, x, buf, w);
  //wattroff (win, color->attr | COLOR_PAIR (color->pair->idx));

  free (buf);
}





/* Get the module/panel label name for the given module enum value.
 *
 * On success, a string containing the label name is returned. */
const char *
module_to_label (GModule module) {
  static const char *modules[] = {
    VISITORS_LABEL,
    REQUESTS_LABEL,
    REQUESTS_STATIC_LABEL,
    NOT_FOUND_LABEL,
    HOSTS_LABEL,
    OS_LABEL,
    BROWSERS_LABEL,
    VISIT_TIMES_LABEL,
    VIRTUAL_HOSTS_LABEL,
    REFERRERS_LABEL,
    REFERRING_SITES_LABEL,
    KEYPHRASES_LABEL,
    STATUS_CODES_LABEL,
    REMOTE_USER_LABEL,
    CACHE_STATUS_LABEL,
#ifdef HAVE_GEOLOCATION
    GEO_LOCATION_LABEL,
    ASN_LABEL,
#endif
    MIME_TYPE_LABEL,
    TLS_TYPE_LABEL,
  };

  return _(modules[module]);
}

/* Get the module/panel label id for the given module enum value.
 *
 * On success, a string containing the label id is returned. */
const char *
module_to_id (GModule module) {
  static const char *modules[] = {
    VISITORS_ID,
    REQUESTS_ID,
    REQUESTS_STATIC_ID,
    NOT_FOUND_ID,
    HOSTS_ID,
    OS_ID,
    BROWSERS_ID,
    VISIT_TIMES_ID,
    VIRTUAL_HOSTS_ID,
    REFERRERS_ID,
    REFERRING_SITES_ID,
    KEYPHRASES_ID,
    STATUS_CODES_ID,
    REMOTE_USER_ID,
    CACHE_STATUS_ID,
#ifdef HAVE_GEOLOCATION
    GEO_LOCATION_ID,
    ASN_ID,
#endif
    MIME_TYPE_ID,
    TLS_TYPE_ID,
  };

  return _(modules[module]);
}

/* Get the module/panel label header for the given module enum value.
 *
 * On success, a string containing the label header is returned. */
const char *
module_to_head (GModule module) {
  static const char *modules[] = {
    VISITORS_HEAD,
    REQUESTS_HEAD,
    REQUESTS_STATIC_HEAD,
    NOT_FOUND_HEAD,
    HOSTS_HEAD,
    OS_HEAD,
    BROWSERS_HEAD,
    VISIT_TIMES_HEAD,
    VIRTUAL_HOSTS_HEAD,
    REFERRERS_HEAD,
    REFERRING_SITES_HEAD,
    KEYPHRASES_HEAD,
    STATUS_CODES_HEAD,
    REMOTE_USER_HEAD,
    CACHE_STATUS_HEAD,
#ifdef HAVE_GEOLOCATION
    GEO_LOCATION_HEAD,
    ASN_HEAD,
#endif
    MIME_TYPE_HEAD,
    TLS_TYPE_HEAD,
  };

  if (!conf.ignore_crawlers)
    modules[VISITORS] = VISITORS_HEAD_BOTS;

  return _(modules[module]);
}

/* Get the module/panel label description for the given module enum
 * value.
 *
 * On success, a string containing the label description is returned. */
const char *
module_to_desc (GModule module) {
  static const char *modules[] = {
    VISITORS_DESC,
    REQUESTS_DESC,
    REQUESTS_STATIC_DESC,
    NOT_FOUND_DESC,
    HOSTS_DESC,
    OS_DESC,
    BROWSERS_DESC,
    VISIT_TIMES_DESC,
    VIRTUAL_HOSTS_DESC,
    REFERRERS_DESC,
    REFERRING_SITES_DESC,
    KEYPHRASES_DESC,
    STATUS_CODES_DESC,
    REMOTE_USER_DESC,
    CACHE_STATUS_DESC,
#ifdef HAVE_GEOLOCATION
    GEO_LOCATION_DESC,
    ASN_DESC,
#endif
    MIME_TYPE_DESC,
    TLS_TYPE_DESC,
  };

  return _(modules[module]);
}



/* Get the overall statistics start and end dates.
 *
 * On failure, 1 is returned
 * On success, 0 is returned and an string containing the overall
 * header is returned. */
int
get_start_end_parsing_dates (char **start, char **end, const char *f) {
  uint32_t *dates = NULL;
  uint32_t len = 0;
  const char *sndfmt = "%Y%m%d";
  char s[DATE_LEN];
  char e[DATE_LEN];

  dates = get_sorted_dates (&len);
  sprintf (s, "%u", dates[0]);
  sprintf (e, "%u", dates[len - 1]);

  /* just display the actual dates - no specificity */
  *start = get_visitors_date (s, sndfmt, f);
  *end = get_visitors_date (e, sndfmt, f);

  free (dates);

  return 0;
}

/* Get the overall statistics header (label).
 *
 * On success, an string containing the overall header is returned. */
char *
get_overall_header (GHolder *h) {
  const char *head = T_DASH_HEAD;
  char *hd = NULL, *start = NULL, *end = NULL;

  if (h->idx == 0 || get_start_end_parsing_dates (&start, &end, "%d/%b/%Y"))
    return xstrdup (head);

  hd = xmalloc (snprintf (NULL, 0, "%s (%s - %s)", head, start, end) + 1);
  sprintf (hd, "%s (%s - %s)", head, start, end);

  free (end);
  free (start);

  return hd;
}



/* Add the given user agent value into our array of GAgents.
 *
 * On error, 1 is returned.
 * On success, the user agent is added to the array and 0 is returned. */
static int
set_agents (void *val, void *user_data) {
  GAgents *agents = user_data;
  GAgentItem *tmp = NULL;
  char *agent = NULL;
  int newlen = 0, i;

  if (!(agent = ht_get_host_agent_val (*(uint32_t *) val)))
    return 1;

  if (agents->size - 1 == agents->idx) {
    newlen = agents->size + 4;
    if (!(tmp = realloc (agents->items, newlen * sizeof (GAgentItem))))
      FATAL ("Unable to realloc agents");

    agents->items = tmp;
    agents->size = newlen;
  }

  for (i = 0; i < agents->idx; ++i) {
    if (strcmp (agent, agents->items[i].agent) == 0) {
      free (agent);
      return 0;
    }
  }
  agents->items[agents->idx++].agent = agent;

  return 0;
}

/* Iterate over the list of agents */
GAgents *
load_host_agents (const char *addr) {
  GAgents *agents = NULL;
  GSLList *keys = NULL, *list = NULL;
  void *data = NULL;
  uint32_t items = 4, key = djb2 ((const unsigned char *) addr);

  keys = ht_get_keymap_list_from_key (HOSTS, key);
  if (!keys)
    return NULL;

  agents = new_gagents (items);

  /* *INDENT-OFF* */
  GSLIST_FOREACH (keys, data, {
    if ((list = ht_get_host_agent_list (HOSTS, (*(uint32_t *) data)))) {
      list_foreach (list, set_agents, agents);
      list_remove_nodes (list);
    }
  });
  /* *INDENT-ON* */
  list_remove_nodes (keys);

  return agents;
}





/* Render the processing spinner. This runs within its own thread. */
static void
ui_spinner (void *ptr_data) {
  GSpinner *sp = (GSpinner *) ptr_data;
 // GColors *color = NULL;

  //static char const spin_chars[] = "/-\\|";
  char buf[SPIN_LBL];
  const char *fn = NULL;
  //int i = 0;
  long long tdiff = 0, psec = 0;
  time_t begin;
  struct timespec ts = {.tv_sec = 0,.tv_nsec = SPIN_UPDATE_INTERVAL };



  time (&begin);
  while (1) {
    pthread_mutex_lock (&sp->mutex);
    if (sp->state == SPN_END) {
      if (!sp->curses && !conf.no_progress)
        fprintf (stderr, "\n");

      pthread_mutex_unlock (&sp->mutex);
      return;
    }

    setlocale (LC_NUMERIC, "");
    if (conf.no_progress) {
      snprintf (buf, sizeof buf, SPIN_FMT, sp->label);
    } else {
      fn = *sp->filename ? *sp->filename : "restoring";
      tdiff = (long long) (time (NULL) - begin);
      psec = tdiff >= 1 ? **(sp->processed) / tdiff : 0;
      snprintf (buf, sizeof buf, SPIN_FMTM, sp->label, fn, **(sp->processed), psec);
    }
    setlocale (LC_NUMERIC, "POSIX");

    if (sp->curses) {
      /* CURSES */
      draw_header (sp->win, buf, " %s", sp->y, sp->x, sp->w, sp->color);
      /* caret */
      //wattron (sp->win, COLOR_PAIR (color->pair->idx));
      //mvwaddch (sp->win, sp->y, sp->spin_x, spin_chars[i++ & 3]);
      //wattroff (sp->win, COLOR_PAIR (color->pair->idx));
      //wrefresh (sp->win);
    } else if (!conf.no_progress) {
      /* STDOUT */
      fprintf (stderr, " \033[K%s\r", buf);
    }

    pthread_mutex_unlock (&sp->mutex);
    if (nanosleep (&ts, NULL) == -1 && errno != EINTR)
      FATAL ("nanosleep: %s", strerror (errno));
  }
}

/* Create the processing spinner's thread */
void
ui_spinner_create (GSpinner *spinner) {
  if (conf.no_parsing_spinner)
    return;

  pthread_create (&(spinner->thread), NULL, (void *) &ui_spinner, spinner);
  pthread_detach (spinner->thread);
}

/* Initialize processing spinner data. */
void
set_curses_spinner (GSpinner *spinner) {
  int y = 0, x = 0;
  if (spinner == NULL)
    return;

  //getmaxyx (stdscr, y, x);

  spinner->color = color_progress;
  spinner->curses = 1;
  spinner->win = 0;
  spinner->x = 0;
  spinner->w = x;
  spinner->spin_x = x - 2;
  spinner->y = y - 1;
}

/* Determine if we need to lock the mutex. */
void
lock_spinner (void) {
  if (parsing_spinner != NULL && parsing_spinner->state == SPN_RUN)
    pthread_mutex_lock (&parsing_spinner->mutex);
}

/* Determine if we need to unlock the mutex. */
void
unlock_spinner (void) {
  if (parsing_spinner != NULL && parsing_spinner->state == SPN_RUN)
    pthread_mutex_unlock (&parsing_spinner->mutex);
}

/* Allocate memory for a spinner instance and initialize its data.
 *
 * On success, the newly allocated GSpinner is returned. */
GSpinner *
new_gspinner (void) {
  GSpinner *spinner;

  spinner = xcalloc (1, sizeof (GSpinner));
  spinner->label = "Parsing...";
  spinner->state = SPN_RUN;
  spinner->curses = 0;
  //if (conf.load_from_disk)
  //  conf.no_progress = 1;

  if (pthread_mutex_init (&(spinner->mutex), NULL))
    FATAL ("Failed init thread mutex");

  return spinner;
}


















