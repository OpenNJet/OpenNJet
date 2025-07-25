#include <benchmark/benchmark.h>
#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>

const int MAX_THREAD = 1;
#define OPERATION_PER_SECOND_LABEL "nb operations per second"

std::string GetEnvironmentVariableOrDefault(const std::string& variable_name,
                                            const std::string& default_value)
{
    const char* value = getenv(variable_name.c_str());
    return value ? value : default_value;
}

std::string DB_PORT = GetEnvironmentVariableOrDefault("TEST_DB_PORT", "3306");
std::string DB_DATABASE = GetEnvironmentVariableOrDefault("TEST_DB_DATABASE", "bench");
std::string DB_USER = GetEnvironmentVariableOrDefault("TEST_DB_USER", "root");
std::string DB_HOST = GetEnvironmentVariableOrDefault("TEST_DB_HOST", "127.0.0.1");
std::string DB_PASSWORD = GetEnvironmentVariableOrDefault("TEST_DB_PASSWORD", "");

#define check_conn_rc(rc, mysql) \
do {\
  if (rc)\
  {\
    fprintf(stdout,"Error (%d): %s (%d) in %s line %d", rc, mysql_error(mysql), \
         mysql_errno(mysql), __FILE__, __LINE__);\
    mysql_close(conn);\
    exit(1);\
  }\
} while(0)


#define check_stmt_rc(rc, stmt, mysql) \
do {\
  if (rc)\
  {\
    fprintf(stdout,"Error (%d): %d (%s) in %s line %d", rc,  mysql_stmt_errno(stmt), \
         mysql_stmt_error(stmt), __FILE__, __LINE__);\
    mysql_close(conn);\
    exit(1);\
  }\
} while(0)

#ifndef BENCHMARK_MYSQL
#include <mysql.h>
const std::string TYPE = "MariaDB";

MYSQL* connect(std::string options) {
  MYSQL *con = mysql_init(NULL);
   if (!(con = mysql_init(0))) {
    fprintf(stderr, "unable to initialize connection struct\n");
    exit(1);
   }

  enum mysql_protocol_type prot_type= MYSQL_PROTOCOL_TCP;
  mysql_optionsv(con, MYSQL_OPT_PROTOCOL, (void *)&prot_type);

  if (mysql_real_connect(con, DB_HOST.c_str(), DB_USER.c_str(), DB_PASSWORD.c_str(),
          DB_DATABASE.c_str(), atoi(DB_PORT.c_str()), NULL, 0) == NULL) {
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
  }
  return con;
}
#endif

#ifdef BENCHMARK_MYSQL
    #include <mysql/mysql.h>
const std::string TYPE = "MySQL";

MYSQL* connect(std::string options) {
  MYSQL *con = mysql_init(NULL);

  if (con == NULL) {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }

  enum mysql_protocol_type prot_type= MYSQL_PROTOCOL_TCP;
  mysql_options(con, MYSQL_OPT_PROTOCOL, (void *)&prot_type);

  if (mysql_real_connect(con, DB_HOST.c_str(), DB_USER.c_str(), DB_PASSWORD.c_str(),
          DB_DATABASE.c_str(), atoi(DB_PORT.c_str()), NULL, 0) == NULL) {
      fprintf(stderr, "%s\n", mysql_error(con));
      mysql_close(con);
      exit(1);
  }
  return con;
}
#endif



void do_1(benchmark::State& state, MYSQL* conn) {
  int rc;
  rc = mysql_query(conn, "DO 1");
  check_conn_rc(rc, conn);

  int id;
  benchmark::DoNotOptimize(id = mysql_insert_id(conn));
}

static void BM_DO_1(benchmark::State& state) {
  MYSQL *conn = connect("");
  int numOperation = 0;
  for (auto _ : state) {
    do_1(state, conn);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

BENCHMARK(BM_DO_1)->Name(TYPE + " DO 1")->ThreadRange(1, MAX_THREAD)->UseRealTime();




void select_1(benchmark::State& state, MYSQL* conn) {
  int rc;
  rc = mysql_query(conn, "SELECT 1");
  check_conn_rc(rc, conn);

  MYSQL_RES *result = mysql_store_result(conn);
  int num_fields = mysql_num_fields(result);

  char* val_name;
  MYSQL_FIELD *field;
  while(field = mysql_fetch_field(result)) {
    benchmark::DoNotOptimize(val_name = field->name);
  }

  int val;
  MYSQL_ROW row;
  while ((row = mysql_fetch_row(result))) {
    for(int i = 0; i < num_fields; i++) {
      benchmark::DoNotOptimize(val = atoi(row[i]));
    }
  }

  mysql_free_result(result);
}

static void BM_SELECT_1(benchmark::State& state) {
  MYSQL *conn = connect("");
  int numOperation = 0;
  for (auto _ : state) {
    select_1(state, conn);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

BENCHMARK(BM_SELECT_1)->Name(TYPE + " SELECT 1")->ThreadRange(1, MAX_THREAD)->UseRealTime();



void select_1000_rows(benchmark::State& state, MYSQL* conn) {
    if (mysql_query(conn, "select seq, 'abcdefghijabcdefghijabcdefghijaa' from seq_1_to_1000")) {
          fprintf(stderr, "%s\n", mysql_error(conn));
          mysql_close(conn);
          exit(1);
    }
    MYSQL_RES *result = mysql_store_result(conn);
    unsigned int num_fields = mysql_num_fields(result);

    if (result == NULL) {
          fprintf(stderr, "%s\n", mysql_error(conn));
          mysql_close(conn);
          exit(1);
    }

    int val1;
    std::string val2;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        benchmark::DoNotOptimize(val1 = atoi(row[0]));
        benchmark::DoNotOptimize(val2 = row[1]);
        benchmark::ClobberMemory();
    }

    mysql_free_result(result);
}

static void BM_SELECT_1000_ROWS(benchmark::State& state) {
  MYSQL *conn = connect("");
  int numOperation = 0;
  for (auto _ : state) {
    select_1000_rows(state, conn);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

BENCHMARK(BM_SELECT_1000_ROWS)->Name(TYPE + " SELECT 1000 rows (int + char(32))")->ThreadRange(1, MAX_THREAD)->UseRealTime();


static void setup_select_100_int_cols(const benchmark::State& state) {
  MYSQL *conn = connect("");
  int rc;

  rc = mysql_query(conn, "DROP TABLE IF EXISTS test100");
  check_conn_rc(rc, conn);

  rc = mysql_query(conn, "CREATE TABLE test100 (i1 int,i2 int,i3 int,i4 int,i5 int,i6 int,i7 int,i8 int,i9 int,i10 int,i11 int,i12 int,i13 int,i14 int,i15 int,i16 int,i17 int,i18 int,i19 int,i20 int,i21 int,i22 int,i23 int,i24 int,i25 int,i26 int,i27 int,i28 int,i29 int,i30 int,i31 int,i32 int,i33 int,i34 int,i35 int,i36 int,i37 int,i38 int,i39 int,i40 int,i41 int,i42 int,i43 int,i44 int,i45 int,i46 int,i47 int,i48 int,i49 int,i50 int,i51 int,i52 int,i53 int,i54 int,i55 int,i56 int,i57 int,i58 int,i59 int,i60 int,i61 int,i62 int,i63 int,i64 int,i65 int,i66 int,i67 int,i68 int,i69 int,i70 int,i71 int,i72 int,i73 int,i74 int,i75 int,i76 int,i77 int,i78 int,i79 int,i80 int,i81 int,i82 int,i83 int,i84 int,i85 int,i86 int,i87 int,i88 int,i89 int,i90 int,i91 int,i92 int,i93 int,i94 int,i95 int,i96 int,i97 int,i98 int,i99 int,i100 int)");
  check_conn_rc(rc, conn);

  rc = mysql_query(conn, "INSERT INTO test100 value (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100)");
  check_conn_rc(rc, conn);

  mysql_close(conn);
}

void select_100_int_cols(benchmark::State& state, MYSQL* conn) {
    int rc;
    rc = mysql_query(conn, "select * FROM test100");
    check_conn_rc(rc, conn);

    MYSQL_RES *result = mysql_store_result(conn);
    unsigned int num_fields = mysql_num_fields(result);

    if (result == NULL) {
          fprintf(stderr, "%s\n", mysql_error(conn));
          mysql_close(conn);
          exit(1);
    }

    int val1;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        for (int i=0; i<100; i++)
            benchmark::DoNotOptimize(val1 = atoi(row[i]));
        benchmark::ClobberMemory();
    }

    mysql_free_result(result);
}

void select_100_int_cols_with_prepare(benchmark::State& state, MYSQL* conn) {
  MYSQL_STMT *stmt = mysql_stmt_init(conn);
  std::string query = "select * FROM test100";
  int rc;

  rc = mysql_stmt_prepare(stmt, query.c_str(), (unsigned long)query.size());
  check_conn_rc(rc, conn);

  int int_data[100];
  unsigned long length[100];

  MYSQL_BIND my_bind[100];
  memset(my_bind, 0, sizeof(my_bind));

  for (int i = 0; i < 100; i++) {
    my_bind[i].buffer_type= MYSQL_TYPE_LONG;
    my_bind[i].buffer= (char *) &int_data[i];
    my_bind[i].length= &length[i];
  }

  rc = mysql_stmt_execute(stmt);
  check_conn_rc(rc, conn);

  rc = mysql_stmt_bind_result(stmt, my_bind);
  check_stmt_rc(rc, stmt, conn);

  rc = mysql_stmt_store_result(stmt);
  check_stmt_rc(rc, stmt, conn);

  while (mysql_stmt_fetch(stmt)) {
    //
  }

  mysql_stmt_close(stmt);
}

void select_100_int_cols_prepared(benchmark::State& state, MYSQL* conn, MYSQL_STMT* stmt) {
  int rc;
  int int_data[100];
  unsigned long length[100];

  MYSQL_BIND my_bind[100];
  memset(my_bind, 0, sizeof(my_bind));

  for (int i = 0; i < 100; i++) {
    my_bind[i].buffer_type= MYSQL_TYPE_LONG;
    my_bind[i].buffer= (char *) &int_data[i];
    my_bind[i].length= &length[i];
  }

  rc = mysql_stmt_execute(stmt);
  check_conn_rc(rc, conn);

  rc = mysql_stmt_bind_result(stmt, my_bind);
  check_stmt_rc(rc, stmt, conn);

  rc = mysql_stmt_store_result(stmt);
  check_stmt_rc(rc, stmt, conn);

  while (mysql_stmt_fetch(stmt)) {
    //
  }
}

static void BM_SELECT_100_INT_COLS(benchmark::State& state) {
  MYSQL *conn = connect("");
  int numOperation = 0;
  for (auto _ : state) {
    select_100_int_cols(state, conn);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

static void BM_SELECT_100_INT_COLS_WITH_PREPARE(benchmark::State& state) {
  MYSQL *conn = connect("");
  int numOperation = 0;
  for (auto _ : state) {
    select_100_int_cols_with_prepare(state, conn);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

static void BM_SELECT_100_INT_COLS_PREPARED(benchmark::State& state) {
  MYSQL *conn = connect("");
  MYSQL_STMT *stmt = mysql_stmt_init(conn);
  std::string query = "select * FROM test100";
  int rc;

  rc = mysql_stmt_prepare(stmt, query.c_str(), (unsigned long)query.size());
  check_conn_rc(rc, conn);
  int numOperation = 0;
  for (auto _ : state) {
    select_100_int_cols_prepared(state, conn, stmt);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_stmt_close(stmt);
  mysql_close(conn);
}

BENCHMARK(BM_SELECT_100_INT_COLS)->Name(TYPE + " SELECT 100 int cols")->ThreadRange(1, MAX_THREAD)->UseRealTime()->Setup(setup_select_100_int_cols);
BENCHMARK(BM_SELECT_100_INT_COLS_WITH_PREPARE)->Name(TYPE + " SELECT 100 int cols - BINARY prepare+execute+close")->ThreadRange(1, MAX_THREAD)->UseRealTime();
BENCHMARK(BM_SELECT_100_INT_COLS_PREPARED)->Name(TYPE + " SELECT 100 int cols - BINARY execute only")->ThreadRange(1, MAX_THREAD)->UseRealTime();




void do_1000_params(benchmark::State& state, MYSQL* conn, const char* query) {
  int rc;
  rc = mysql_query(conn, query);
  check_conn_rc(rc, conn);

  int id;
  benchmark::DoNotOptimize(id = mysql_insert_id(conn));
}

static void BM_DO_1000_PARAMS(benchmark::State& state) {
  MYSQL *conn = connect("");
  std::string query = "DO 1";
  for (int i = 1; i < 1000; i++) {
    query += "," + std::to_string(i);
  }
  const char* queryChar = query.c_str();
  int rc;

  int numOperation = 0;
  for (auto _ : state) {
    do_1000_params(state, conn, queryChar);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

BENCHMARK(BM_DO_1000_PARAMS)->Name(TYPE + " DO 1000 params")->ThreadRange(1, MAX_THREAD)->UseRealTime();




static void setup_insert_batch(const benchmark::State& state) {
  MYSQL *conn = connect("");
  int rc;

  rc = mysql_query(conn, "DROP TABLE IF EXISTS perfTestTextBatch");
  check_conn_rc(rc, conn);

  rc = mysql_query(conn, "INSTALL SONAME 'ha_blackhole'");
  rc = mysql_query(conn, "CREATE TABLE perfTestTextBatch (id MEDIUMINT NOT NULL AUTO_INCREMENT,t0 text, PRIMARY KEY (id)) COLLATE='utf8mb4_unicode_ci' ENGINE = BLACKHOLE");
  if (rc) {
    rc = mysql_query(conn, "CREATE TABLE perfTestTextBatch (id MEDIUMINT NOT NULL AUTO_INCREMENT,t0 text, PRIMARY KEY (id)) COLLATE='utf8mb4_unicode_ci'");
    check_conn_rc(rc, conn);
  }
  mysql_close(conn);
}

std::vector<std::string> chars = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "\\Z", "😎", "🌶", "🎤", "🥂" };

std::string randomString(int length) {
    std::string result = "";
    for (int i = length; i > 0; --i) {
        result += chars[rand() % (chars.size() - 1)];
    }
    return result;
}

void insert_batch_with_prepare(benchmark::State& state, MYSQL* conn) {
  MYSQL_STMT *stmt = mysql_stmt_init(conn);
  std::string query = "INSERT INTO perfTestTextBatch(t0) VALUES (?)";
  int rc;

  rc = mysql_stmt_prepare(stmt, query.c_str(), (unsigned long)query.size());
  check_conn_rc(rc, conn);

  std::string randomStringVal = randomString(100);
  char* randValue = (char *)randomStringVal.c_str();
  long unsigned randValueLen = randomStringVal.length();
  MYSQL_BIND my_bind[1];
  memset(my_bind, 0, sizeof(my_bind));

  my_bind[0].buffer_type= MYSQL_TYPE_STRING;
  my_bind[0].buffer= randValue;
  my_bind[0].length= &randValueLen;

  for (int i = 0; i < 100; i++) {
    rc = mysql_stmt_bind_param(stmt, my_bind);
    check_stmt_rc(rc, stmt, conn);

    rc = mysql_stmt_execute(stmt);
    check_conn_rc(rc, conn);
  }
  mysql_stmt_close(stmt);
}

static void BM_INSERT_BATCH_WITH_PREPARE(benchmark::State& state) {
  MYSQL *conn = connect("");
  int numOperation = 0;
  for (auto _ : state) {
    insert_batch_with_prepare(state, conn);
    numOperation++;
  }
  state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
  mysql_close(conn);
}

BENCHMARK(BM_INSERT_BATCH_WITH_PREPARE)->Name(TYPE + " insert batch looping execute")->ThreadRange(1, MAX_THREAD)->UseRealTime()->Setup(setup_insert_batch);

#ifndef BENCHMARK_MYSQL

  void insert_bulk_batch_with_prepare(benchmark::State& state, MYSQL* conn, MYSQL_STMT *stmt) {
    int rc;
    std::string randomStringVal = randomString(100);
    char* randValue = (char *)randomStringVal.c_str();
    long randValueLen = randomStringVal.length();

    unsigned int numrows = 100;
    long unsigned value_len[100];
    char *valueptr[100];
    for (int i = 0; i < 100; i++) {
      valueptr[i]= randValue;
      value_len[i]= randValueLen;
    }

    MYSQL_BIND my_bind[1];
    memset(my_bind, 0, sizeof(my_bind));
    my_bind[0].u.indicator = 0;
    my_bind[0].buffer_type= MYSQL_TYPE_STRING;
    my_bind[0].buffer= valueptr;
    my_bind[0].length= value_len;

    rc = mysql_stmt_bind_param(stmt, my_bind);
    check_stmt_rc(rc, stmt, conn);

    mysql_stmt_attr_set(stmt, STMT_ATTR_ARRAY_SIZE, &numrows);
    rc = mysql_stmt_execute(stmt);
    check_conn_rc(rc, conn);
  }

  static void BM_INSERT_BULK_BATCH_WITH_PREPARE(benchmark::State& state) {
    MYSQL *conn = connect("");
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    std::string query = "INSERT INTO perfTestTextBatch(t0) VALUES (?)";
    int rc;

    rc = mysql_stmt_prepare(stmt, query.c_str(), (unsigned long)query.size());
    check_conn_rc(rc, conn);

    int numOperation = 0;
    for (auto _ : state) {
      insert_bulk_batch_with_prepare(state, conn, stmt);
      numOperation++;
    }
    state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
    mysql_stmt_close(stmt);
    mysql_close(conn);
  }
  BENCHMARK(BM_INSERT_BULK_BATCH_WITH_PREPARE)->Name(TYPE + " insert batch using bulk")->ThreadRange(1, MAX_THREAD)->UseRealTime()->Setup(setup_insert_batch);

  void select_100_int_cols_with_prepare_pipeline(benchmark::State& state, MYSQL* conn) {
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    std::string query = "select * FROM test100";
    int rc;

    int int_data[100];
    unsigned long length[100];

    MYSQL_BIND my_bind[100];
    memset(my_bind, 0, sizeof(my_bind));

    for (int i = 0; i < 100; i++) {
      my_bind[i].buffer_type= MYSQL_TYPE_LONG;
      my_bind[i].buffer= (char *) &int_data[i];
      my_bind[i].length= &length[i];
    }

    rc = mariadb_stmt_execute_direct(stmt, query.c_str(), (unsigned long)query.size());
    check_conn_rc(rc, conn);

    rc = mysql_stmt_bind_result(stmt, my_bind);
    check_stmt_rc(rc, stmt, conn);

    rc = mysql_stmt_store_result(stmt);
    check_stmt_rc(rc, stmt, conn);

    while (mysql_stmt_fetch(stmt)) {
      //
    }

    mysql_stmt_close(stmt);
  }


  static void BM_SELECT_100_INT_COLS_WITH_PREPARE_PIPELINE(benchmark::State& state) {
    MYSQL *conn = connect("");
    int numOperation = 0;
    for (auto _ : state) {
      select_100_int_cols_with_prepare_pipeline(state, conn);
      numOperation++;
    }
    state.counters[OPERATION_PER_SECOND_LABEL] = benchmark::Counter(numOperation, benchmark::Counter::kIsRate);
    mysql_close(conn);
  }

  BENCHMARK(BM_SELECT_100_INT_COLS_WITH_PREPARE_PIPELINE)->Name(TYPE + " SELECT 100 int cols - BINARY pipeline prepare+execute+close")->ThreadRange(1, MAX_THREAD)->UseRealTime()->Setup(setup_insert_batch);

#endif


BENCHMARK_MAIN();
