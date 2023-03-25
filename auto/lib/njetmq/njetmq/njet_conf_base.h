#ifndef _CONF_BASE_H_
#define _CONF_BASE_H_

int conf__parse_bool(char **token, const char *name, bool *value, char *saveptr);
int conf__parse_int(char **token, const char *name, int *value, char *saveptr);
int conf__parse_ssize_t(char **token, const char *name, ssize_t *value, char *saveptr);
int conf__parse_string(char **token, const char *name, char **value, char *saveptr);
#endif
