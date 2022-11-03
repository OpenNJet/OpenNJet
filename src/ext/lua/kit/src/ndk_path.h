

/* path conversion functions */

void            ndk_clean_path                  (njt_str_t *path, njt_uint_t complex, size_t off);
void            ndk_path_to_dir_safe            (njt_str_t *path, njt_uint_t complex, size_t off);

/* path create functions */

njt_array_t *   ndk_split_path_create           (njt_conf_t *cf, njt_str_t *path);
njt_array_t *   ndk_split_path_create_raw       (njt_conf_t *cf, char *path);

/* conf set functions */

char *          ndk_conf_set_full_path_slot     (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *          ndk_conf_set_split_path_slot    (njt_conf_t *cf, njt_command_t *cmd, void *conf);

/* conf set post functions */

char *          ndk_conf_set_full_path          (njt_conf_t *cf, void *data, njt_str_t *path);
char *          ndk_conf_set_full_conf_path     (njt_conf_t *cf, void *data, njt_str_t *path);

