/*
Copyright (c) 2018 MariaDB Corporation AB

The MySQL Connector/C is licensed under the terms of the GPLv2
<http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>, like most
MySQL Connectors. There are special exceptions to the terms and
conditions of the GPLv2 as it is applied to this software, see the
FLOSS License Exception
<http://www.mysql.com/about/legal/licensing/foss-exception.html>.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/
/**
  Some basic tests of the client API.
*/

#include "my_test.h"
#include "mariadb_rpl.h"

static int test_rpl_async(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  MYSQL_RES *result;
  MYSQL_ROW row;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;
  int events= 0, rc;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rc= mysql_query(mysql, "SELECT @@log_bin");
  check_mysql_rc(rc, mysql);

  result= mysql_store_result(mysql);
  row= mysql_fetch_row(result);
  if (!atoi(row[0]))
    rc= SKIP;
  mysql_free_result(result);

  if (rc == SKIP)
  {
    diag("binary log disabled -> skip");
    mysql_close(mysql);
    return SKIP;
  }

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  /* We run rpl_api as very last test, too make sure
     binary log contains > 10000 events.
   */
  while((event= mariadb_rpl_fetch(rpl, event)) && events < 10000)
  {
    events++;
  }
  mariadb_free_rpl_event(event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return OK;
}

static int test_rpl_semisync(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  MYSQL_RES *result;
  MYSQL_ROW row;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;
  int events= 0, rc;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rc= mysql_query(mysql, "SELECT @@log_bin");
  check_mysql_rc(rc, mysql);

  result= mysql_store_result(mysql);
  row= mysql_fetch_row(result);
  if (!atoi(row[0]))
    rc= SKIP;
  mysql_free_result(result);

  if (rc == SKIP)
  {
    diag("binary log disabled -> skip");
    mysql_close(mysql);
    return SKIP;
  }

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  mysql_query(mysql, "SET @rpl_semi_sync_slave=1");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  /* We run rpl_api as very last test, too make sure
     binary log contains > 10000 events.
   */
  while((event= mariadb_rpl_fetch(rpl, event)) && events < 10000)
  {
    events++;
  }
  mariadb_free_rpl_event(event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return OK;
}

static int test_conc467(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  MYSQL_RES *result;
  MYSQL_ROW row;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;
  int rc;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rc= mysql_query(mysql, "SELECT @@log_bin");
  check_mysql_rc(rc, mysql);

  result= mysql_store_result(mysql);
  row= mysql_fetch_row(result);
  if (!atoi(row[0]))
    rc= SKIP;
  mysql_free_result(result);

  if (rc == SKIP)
  {
    diag("binary log disabled -> skip");
    mysql_close(mysql);
    return SKIP;
  }

  /* Force to create a log rotate event */
  rc= mysql_query(mysql, "FLUSH logs");
  check_mysql_rc(rc, mysql);

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  mysql_query(mysql, "SET @rpl_semi_sync_slave=1");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  if (!(event= mariadb_rpl_fetch(rpl, event)))
    rc= FAIL;
  else
  {
    if (!rpl->filename)
    {
      diag("error: filename not set");
      rc= FAIL;
    }
    else
      diag("filename: %.*s", (int)rpl->filename_length, rpl->filename);
  }

  mariadb_free_rpl_event(event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return rc;
}

struct my_tests_st my_tests[] = {
  {"test_rpl_async", test_rpl_async, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {"test_rpl_semisync", test_rpl_semisync, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {"test_conc467", test_conc467, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};


int main(int argc, char **argv)
{
  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  return(exit_status());
}
