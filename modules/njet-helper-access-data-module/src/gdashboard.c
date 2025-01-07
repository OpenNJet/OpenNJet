/**
 * gdashboard.c -- goaccess main dashboard
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

#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <regex.h>
#include <inttypes.h>

#include "gdashboard.h"

#include "gkhash.h"
#include "gholder.h"
#include "color.h"
#include "error.h"
#include "gstorage.h"
#include "util.h"
#include "xmalloc.h"

static GFind find_t;

/* Reset find indices */
void
reset_find (void) {
  if (find_t.pattern != NULL && *find_t.pattern != '\0')
    free (find_t.pattern);

  find_t.look_in_sub = 0;
  find_t.module = 0;
  find_t.next_idx = 0;  /* next total index    */
  find_t.next_parent_idx = 0;   /* next parent index   */
  find_t.next_sub_idx = 0;      /* next sub item index */
  find_t.pattern = NULL;
}

/* Allocate memory for a new GDash instance.
 *
 * On success, the newly allocated GDash is returned . */
GDash *
new_gdash (void) {
  GDash *dash = xmalloc (sizeof (GDash));
  memset (dash, 0, sizeof *dash);
  dash->total_alloc = 0;

  return dash;
}

/* Allocate memory for a new GDashData instance.
 *
 * On success, the newly allocated GDashData is returned . */
GDashData *
new_gdata (uint32_t size) {
  GDashData *data = xcalloc (size, sizeof (GDashData));

  return data;
}

/* Free memory allocated for a GDashData instance. Includes malloc'd
 * strings. */
static void
free_dashboard_data (GDashData item) {
  if (item.metrics == NULL)
    return;

  if (item.metrics->data)
    free (item.metrics->data);
  if (item.metrics->bw.sbw)
    free (item.metrics->bw.sbw);
  if (conf.serve_usecs && item.metrics->avgts.sts)
    free (item.metrics->avgts.sts);
  if (conf.serve_usecs && item.metrics->cumts.sts)
    free (item.metrics->cumts.sts);
  if (conf.serve_usecs && item.metrics->maxts.sts)
    free (item.metrics->maxts.sts);
  free (item.metrics);
}

/* Free memory allocated for a GDash instance, and nested structure
 * data. */
void
free_dashboard (GDash *dash) {
  GModule module;
  int j;
  size_t idx = 0;

  FOREACH_MODULE (idx, module_list) {
    module = module_list[idx];
    for (j = 0; j < dash->module[module].alloc_data; j++) {
      free_dashboard_data (dash->module[module].data[j]);
    }
    free (dash->module[module].data);
  }
  free (dash);
}

/* Get the current panel/module given the `Y` offset (position) in the
 * terminal dashboard.
 *
 * If not found, 0 is returned.
 * If found, the module number is returned . */
static GModule
get_find_current_module (GDash *dash, int offset) {
  GModule module;
  size_t idx = 0;

  FOREACH_MODULE (idx, module_list) {
    module = module_list[idx];

    /* set current module */
    if (dash->module[module].pos_y == offset)
      return module;
    /* we went over by one module, set current - 1 */
    if (dash->module[module].pos_y > offset)
      return module - 1;
  }

  return 0;
}

/* Get the number of rows that a collapsed dashboard panel contains.
 *
 * On success, the number of rows is returned. */
int
get_num_collapsed_data_rows (void) {
  /* The default number of rows is fixed */
  int size = DASH_COLLAPSED - DASH_NON_DATA;
  /* If no column names, then add the number of rows occupied by the
   * column values to the default number */
  return conf.no_column_names ? size + DASH_COL_ROWS : size;
}

/* Get the number of rows that an expanded dashboard panel contains.
 *
 * On success, the number of rows is returned. */
int
get_num_expanded_data_rows (void) {
  /* The default number of rows is fixed */
  int size = DASH_EXPANDED - DASH_NON_DATA;
  /* If no column names, then add the number of rows occupied by the
   * column values to the default number */
  return conf.no_column_names ? size + DASH_COL_ROWS : size;
}




/* Determine which module should be expanded given the current mouse
 * position.
 *
 * On error, 1 is returned.
 * On success, 0 is returned. */
int
set_module_from_mouse_event (GScroll *gscroll, GDash *dash, int y) {
  int module = 0;
  int offset = y - MAX_HEIGHT_HEADER - MAX_HEIGHT_FOOTER + 1;
  if (gscroll->expanded) {
    module = get_find_current_module (dash, offset);
  } else {
    offset += gscroll->dash;
    module = offset / DASH_COLLAPSED;
  }

  if (module >= TOTAL_MODULES)
    module = TOTAL_MODULES - 1;
  else if (module < 0)
    module = 0;

  if ((int) gscroll->current == module)
    return 1;

  gscroll->current = module;
  return 0;
}

/* Allocate a new string for a sub item on the terminal dashboard.
 *
 * On error, NULL is returned.
 * On success, the newly allocated string is returned. */
static char *
render_child_node (const char *data) {
  char *buf;
  int len = 0;

  /* chars to use based on encoding used */
#ifdef HAVE_LIBNCURSESW
  const char *bend = "\xe2\x94\x9c";
  const char *horz = "\xe2\x94\x80";
#else
  const char *bend = "|";
  const char *horz = "`-";
#endif

  if (data == NULL || *data == '\0')
    return NULL;

  len = snprintf (NULL, 0, " %s%s %s", bend, horz, data);
  buf = xmalloc (len + 3);
  sprintf (buf, " %s%s %s", bend, horz, data);

  return buf;
}



/* Get largest hits metric.
 *
 * On error, 0 is returned.
 * On success, largest hits metric is returned. */
static void
set_max_metrics (GDashMeta *meta, GDashData *idata) {
  if (meta->max_hits < idata->metrics->hits)
    meta->max_hits = idata->metrics->hits;
  if (meta->max_visitors < idata->metrics->visitors)
    meta->max_visitors = idata->metrics->visitors;
}

/* Set largest hits metric (length of the integer). */
static void
set_max_hit_len (GDashMeta *meta, GDashData *idata) {
  int vlen = intlen (idata->metrics->hits);
  int llen = strlen (MTRC_HITS_LBL);

  if (vlen > meta->hits_len)
    meta->hits_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->hits_len)
    meta->hits_len = llen;
}

/* Get the percent integer length. */
static void
set_max_hit_perc_len (GDashMeta *meta, GDashData *idata) {
  int vlen = intlen (idata->metrics->hits_perc);
  int llen = strlen (MTRC_HITS_PERC_LBL);

  if (vlen > meta->hits_perc_len)
    meta->hits_perc_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->hits_perc_len)
    meta->hits_perc_len = llen;
}

/* Set largest hits metric (length of the integer). */
static void
set_max_visitors_len (GDashMeta *meta, GDashData *idata) {
  int vlen = intlen (idata->metrics->visitors);
  int llen = strlen (MTRC_VISITORS_SHORT_LBL);

  if (vlen > meta->visitors_len)
    meta->visitors_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->visitors_len)
    meta->visitors_len = llen;
}

/* Get the percent integer length. */
static void
set_max_visitors_perc_len (GDashMeta *meta, GDashData *idata) {
  int vlen = intlen (idata->metrics->visitors_perc);
  int llen = strlen (MTRC_VISITORS_PERC_LBL);

  if (vlen > meta->visitors_perc_len)
    meta->visitors_perc_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->visitors_perc_len)
    meta->visitors_perc_len = llen;
}

/* Get the percent integer length. */
static void
set_max_bw_len (GDashMeta *meta, GDashData *idata) {
  int vlen = strlen (idata->metrics->bw.sbw);
  int llen = strlen (MTRC_BW_LBL);

  if (vlen > meta->bw_len)
    meta->bw_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->bw_len)
    meta->bw_len = llen;
}

/* Get the percent integer length. */
static void
set_max_avgts_len (GDashMeta *meta, GDashData *idata) {
  int vlen = 0, llen = 0;

  if (!conf.serve_usecs || !idata->metrics->avgts.sts)
    return;

  vlen = strlen (idata->metrics->avgts.sts);
  llen = strlen (MTRC_AVGTS_LBL);

  if (vlen > meta->avgts_len)
    meta->avgts_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->avgts_len)
    meta->avgts_len = llen;
}

/* Get the percent integer length. */
static void
set_max_cumts_len (GDashMeta *meta, GDashData *idata) {
  int vlen = 0, llen = 0;

  if (!conf.serve_usecs || !idata->metrics->cumts.sts)
    return;

  vlen = strlen (idata->metrics->cumts.sts);
  llen = strlen (MTRC_AVGTS_LBL);

  if (vlen > meta->cumts_len)
    meta->cumts_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->cumts_len)
    meta->cumts_len = llen;
}

/* Get the percent integer length. */
static void
set_max_maxts_len (GDashMeta *meta, GDashData *idata) {
  int vlen = 0, llen = 0;

  if (!conf.serve_usecs || !idata->metrics->maxts.sts)
    return;

  vlen = strlen (idata->metrics->maxts.sts);
  llen = strlen (MTRC_AVGTS_LBL);

  if (vlen > meta->maxts_len)
    meta->maxts_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->maxts_len)
    meta->maxts_len = llen;
}

/* Get the percent integer length. */
static void
set_max_method_len (GDashMeta *meta, GDashData *idata) {
  int vlen = 0, llen = 0;

  if (!conf.append_method || !idata->metrics->method)
    return;

  vlen = strlen (idata->metrics->method);
  llen = strlen (MTRC_METHODS_SHORT_LBL);

  if (vlen > meta->method_len)
    meta->method_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->method_len)
    meta->method_len = llen;
}

/* Get the percent integer length. */
static void
set_max_protocol_len (GDashMeta *meta, GDashData *idata) {
  int vlen = 0, llen = 0;

  if (!conf.append_protocol || !idata->metrics->protocol)
    return;

  vlen = strlen (idata->metrics->protocol);
  llen = strlen (MTRC_PROTOCOLS_SHORT_LBL);

  if (vlen > meta->protocol_len)
    meta->protocol_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->protocol_len)
    meta->protocol_len = llen;
}

/* Get the percent integer length. */
static void
set_max_data_len (GDashMeta *meta, GDashData *idata) {
  int vlen = 0, llen = 0;

  vlen = strlen (idata->metrics->data);
  llen = strlen (MTRC_DATA_LBL);

  if (vlen > meta->data_len)
    meta->data_len = vlen;

  /* if outputting with column names, then determine if the value is
   * longer than the length of the column name */
  if (llen > meta->data_len)
    meta->data_len = llen;
}

static void
set_metrics_len (GDashMeta *meta, GDashData *idata) {
  /* integer-based length */
  set_max_hit_len (meta, idata);
  set_max_hit_perc_len (meta, idata);
  set_max_visitors_len (meta, idata);
  set_max_visitors_perc_len (meta, idata);

  /* string-based length */
  set_max_bw_len (meta, idata);
  set_max_avgts_len (meta, idata);
  set_max_cumts_len (meta, idata);
  set_max_maxts_len (meta, idata);

  set_max_method_len (meta, idata);
  set_max_protocol_len (meta, idata);
  set_max_data_len (meta, idata);
}





























/* Reset the scroll and offset fields for each panel/module. */
void
reset_scroll_offsets (GScroll *gscroll) {
  GModule module;
  size_t idx = 0;

  FOREACH_MODULE (idx, module_list) {
    module = module_list[idx];

    gscroll->module[module].scroll = 0;
    gscroll->module[module].offset = 0;
  }
}

/* Compile the regular expression and see if it's valid.
 *
 * If unable to compile, an error as described in <regex.h>.
 * Upon successful completion, function returns 0. */
static int
regexp_init (regex_t *regex, const char *pattern) {
  int rc;
  char buf[REGEX_ERROR];

  //getmaxyx (stdscr, y, x);
  rc = regcomp (regex, pattern, REG_EXTENDED | (find_t.icase ? REG_ICASE : 0));
  /* something went wrong */
  if (rc != 0) {
    regerror (rc, regex, buf, sizeof (buf));
    //draw_header (stdscr, buf, "%s", y - 1, 0, x, color_error);
    //refresh ();
    return 1;
  }
  return 0;
}

/* Set the dashboard scroll and offset based on the search index. */
static void
perform_find_dash_scroll (GScroll *gscroll, GModule module) {
  int *scrll, *offset;
  int exp_size = get_num_expanded_data_rows ();

  /* reset gscroll offsets if we are changing module */
  if (gscroll->current != module)
    reset_scroll_offsets (gscroll);

  scrll = &gscroll->module[module].scroll;
  offset = &gscroll->module[module].offset;

  (*scrll) = find_t.next_idx;
  if (*scrll >= exp_size && *scrll >= *offset + exp_size)
    (*offset) = (*scrll) < exp_size - 1 ? 0 : (*scrll) - exp_size + 1;

  gscroll->current = module;
  gscroll->dash = get_module_index (module) * DASH_COLLAPSED;
  gscroll->expanded = 1;
  find_t.module = module;
}

/* Find the searched item within the given sub list.
 *
 * If not found, the GFind structure is reset and 1 is returned.
 * If found, a GFind structure is set and 0 is returned. */
static int
find_next_sub_item (GSubList *sub_list, regex_t *regex) {
  GSubItem *iter;
  int i = 0, rc;

  if (sub_list == NULL)
    goto out;

  for (iter = sub_list->head; iter; iter = iter->next) {
    if (i >= find_t.next_sub_idx) {
      rc = regexec (regex, iter->metrics->data, 0, NULL, 0);
      if (rc == 0) {
        find_t.next_idx++;
        find_t.next_sub_idx = (1 + i);
        return 0;
      }
      find_t.next_idx++;
    }
    i++;
  }
out:
  find_t.next_parent_idx++;
  find_t.next_sub_idx = 0;
  find_t.look_in_sub = 0;

  return 1;
}

/* Perform a forward search across all modules.
 *
 * On error or if not found, 1 is returned.
 * On success or if found, a GFind structure is set and 0 is returned. */
int
perform_next_find (GHolder *h, GScroll *gscroll) {
  GModule module;
  GSubList *sub_list;
  regex_t regex;
  char buf[REGEX_ERROR], *data;
  int j, n, rc;
  size_t idx = 0;

  //getmaxyx (stdscr, y, x);

  if (find_t.pattern == NULL || *find_t.pattern == '\0')
    return 1;

  /* compile and initialize regexp */
  if (regexp_init (&regex, find_t.pattern))
    return 1;

  /* use last find_t.module and start search */
  idx = find_t.module;
  FOREACH_MODULE (idx, module_list) {
    module = module_list[idx];

    n = h[module].idx;
    for (j = find_t.next_parent_idx; j < n; j++, find_t.next_idx++) {
      data = h[module].items[j].metrics->data;

      rc = regexec (&regex, data, 0, NULL, 0);
      /* error matching against the precompiled pattern buffer */
      if (rc != 0 && rc != REG_NOMATCH) {
        regerror (rc, &regex, buf, sizeof (buf));
        //draw_header (stdscr, buf, "%s", y - 1, 0, x, color_error);
        //refresh ();
        regfree (&regex);
        return 1;
      }
      /* a match was found (data level) */
      else if (rc == 0 && !find_t.look_in_sub) {
        find_t.look_in_sub = 1;
        perform_find_dash_scroll (gscroll, module);
        goto out;
      }
      /* look at sub list nodes */
      else {
        sub_list = h[module].items[j].sub_list;
        if (find_next_sub_item (sub_list, &regex) == 0) {
          perform_find_dash_scroll (gscroll, module);
          goto out;
        }
      }
    }

    /* reset find */
    find_t.next_idx = 0;
    find_t.next_parent_idx = 0;
    find_t.next_sub_idx = 0;

    if (find_t.module != module) {
      reset_scroll_offsets (gscroll);
      gscroll->expanded = 0;
    }
    if (module == TOTAL_MODULES - 1) {
      find_t.module = 0;
      goto out;
    }
  }

out:
  regfree (&regex);
  return 0;
}



static void
set_dash_metrics (GDash **dash, GMetrics *metrics, GModule module,
                  GPercTotals totals, int is_subitem) {
  GDashData *idata = NULL;
  GDashMeta *meta = NULL;
  char *data = NULL;
  int *idx;

  data = is_subitem ? render_child_node (metrics->data) : metrics->data;
  if (!data)
    return;

  idx = &(*dash)->module[module].idx_data;
  idata = &(*dash)->module[module].data[(*idx)];
  meta = &(*dash)->module[module].meta;

  idata->metrics = new_gmetrics (0);
  idata->is_subitem = is_subitem;

  idata->metrics->hits = metrics->hits;
  idata->metrics->hits_perc = get_percentage (totals.hits, metrics->hits);
  idata->metrics->visitors = metrics->visitors;
  idata->metrics->visitors_perc = get_percentage (totals.visitors, metrics->visitors);
  idata->metrics->bw.sbw = filesize_str (metrics->bw.nbw);
  idata->metrics->data = xstrdup (data);

  if (conf.append_method && metrics->method)
    idata->metrics->method = metrics->method;
  if (conf.append_protocol && metrics->protocol)
    idata->metrics->protocol = metrics->protocol;

  if (!conf.serve_usecs)
    goto out;

  idata->metrics->avgts.sts = usecs_to_str (metrics->avgts.nts);
  idata->metrics->cumts.sts = usecs_to_str (metrics->cumts.nts);
  idata->metrics->maxts.sts = usecs_to_str (metrics->maxts.nts);

out:
  if (is_subitem)
    free (data);

  set_metrics_len (meta, idata);
  set_max_metrics (meta, idata);

  (*idx)++;
}

/* Add an item from a sub list to the dashboard.
 *
 * If no items on the sub list, the function returns.
 * On success, sub list data is set into the dashboard structure. */
static void
add_sub_item_to_dash (GDash **dash, GHolderItem item, GModule module, GPercTotals totals,
                      int *i) {
  GSubList *sub_list = item.sub_list;
  GSubItem *iter;

  if (sub_list == NULL)
    return;

  for (iter = sub_list->head; iter; iter = iter->next, (*i)++) {
    set_dash_metrics (dash, iter->metrics, module, totals, 1);
  }
}

/* Add a first level item to dashboard.
 *
 * On success, data is set into the dashboard structure. */
static void
add_item_to_dash (GDash **dash, GHolderItem item, GModule module, GPercTotals totals) {
  set_dash_metrics (dash, item.metrics, module, totals, 0);
}

/* Load holder's data into the dashboard structure. */
void
load_data_to_dash (GHolder *h, GDash *dash, GModule module, GScroll *gscroll) {
  int alloc_size = 0;
  int i, j;
  GPercTotals totals;

  alloc_size = dash->module[module].alloc_data;
  if (gscroll->expanded && module == gscroll->current)
    alloc_size += h->sub_items_size;

  dash->module[module].alloc_data = alloc_size;
  dash->module[module].data = new_gdata (alloc_size);
  dash->module[module].holder_size = h->holder_size;
  memset (&dash->module[module].meta, 0, sizeof (GDashData));

  set_module_totals (&totals);

  for (i = 0, j = 0; i < alloc_size; i++) {
    if (h->items[j].metrics->data == NULL)
      continue;

    add_item_to_dash (&dash, h->items[j], module, totals);
    if (gscroll->expanded && module == gscroll->current && h->sub_items_size)
      add_sub_item_to_dash (&dash, h->items[j], module, totals, &i);
    j++;
  }
}
