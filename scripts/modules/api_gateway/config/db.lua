return {
    db_file = (njt.config.data_prefix and njt.config.data_prefix() or njt.config.prefix()).."/apigw_data/api_gateway.db"
}