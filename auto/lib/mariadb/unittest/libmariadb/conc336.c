#include "my_test.h"

#define MAX_COUNT 2000

int main(int argc, char *argv[]) {

	MYSQL *mysql;
	int i;

  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  if (IS_XPAND())
    SKIP_XPAND;

  if (IS_SKYSQL(hostname))
    return 0;

  if (IS_XPAND())
    SKIP_XPAND;

  diag("hostname: %s", hostname);

	for (i = 0; i < MAX_COUNT; ++i) {

		if (mysql_library_init(-1, NULL, NULL) != 0) {
			diag("mysql_library_init failed");
			return 1;
		}

		mysql = mysql_init(NULL);
		if (!mysql) {
			diag("mysql_init failed");
			return 1;
		}

    if (force_tls)
      mysql_options(mysql, MYSQL_OPT_SSL_ENFORCE, &force_tls);

		if (!mysql_real_connect(mysql, hostname, username, password, schema, port, socketname, 0)) {
			diag("mysql_real_connect failed: %s", mysql_error(mysql));
			return 1;
		}

		if (mysql_query(mysql, "SELECT NULL LIMIT 0") != 0) {
			diag("mysql_query failed: %s", mysql_error(mysql));
			return 1;
		}

		mysql_close(mysql);
		mysql_library_end();

	}

	return 0;

}
