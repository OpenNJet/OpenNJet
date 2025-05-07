return {
    HEADER_USER_ID = "APIGW-User-Id",
    CONFIG_CHANGES_SESSION_KEY = "APIGW-Config-DB-Changes",
    APP_CONFIG_CHANGES_KEY_PREFIX = "APIGW-App-Config-Changes-",
    APPS_FOLDER = (njt.config.data_prefix and njt.config.data_prefix() or njt.config.prefix()) .. "apps",
    APPS_FOLDER_WITHOUT_PREFIX = "apps",
    APP_SCHEMA_FILE = "app_schema.json",
}

