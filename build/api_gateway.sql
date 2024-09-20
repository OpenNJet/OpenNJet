DROP TABLE if exists api_user;
CREATE TABLE api_user (
   id INTEGER PRIMARY KEY,
   name TEXT UNIQUE NOT NULL ,
   password TEXT NOT NULL ,
   email TEXT UNIQUE,
   mobile TEXT UNIQUE
);

DROP TABLE if exists api_user_group;
CREATE TABLE api_user_group (
   id INTEGER PRIMARY KEY,
   name TEXT UNIQUE NOT NULL,
   desc TEXT 
);

DROP TABLE if exists api_user_group_rel;
CREATE TABLE api_user_group_rel (
   id INTEGER PRIMARY KEY,
   user_id INTEGER NOT NULL,
   group_id INTEGER NOT NULL
);

DROP TABLE if exists api_role;
CREATE TABLE api_role (
   id INTEGER PRIMARY KEY,
   name TEXT UNIQUE NOT NULL,
   desc TEXT 
);

DROP TABLE if exists api_user_group_role_rel;
CREATE TABLE api_user_group_role_rel (
   id INTEGER PRIMARY KEY,
   group_id INTEGER NOT NULL,
   role_id INTEGER NOT NULL
);

DROP TABLE if exists api_group;
CREATE TABLE api_group (
   id INTEGER PRIMARY KEY,
   name TEXT NOT NULL UNIQUE,
   base_path TEXT NOT NULL UNIQUE, 
   desc TEXT,
   user_id INTEGER
);

DROP TABLE if exists api;
CREATE TABLE api (
   id INTEGER PRIMARY KEY,
   name TEXT NOT NULL ,
   group_id INTEGER NOT NULL ,
   path TEXT NOT NULL ,
   method TEXT NOT NULL,
   desc TEXT,
   param_mode INTEGER DEFAULT 0,  -- 0 参数透传，1 参数映射 （过滤未知参数）， 2 参数映射 （透传未知参数）
   sign_validation INTEGER DEFAULT 0,
   UNIQUE(group_id, path, method)
);

DROP TABLE if exists api_grant_mode;
CREATE TABLE api_grant_mode (
  id INTEGER PRIMARY KEY,
  api_id INTEGER NOT NULL, 
  grant_mode INTEGER DEFAULT 1,  -- 0 无校验， 1 rbac, 2 cookie
  properties TEXT 
);

DROP TABLE if exists api_grant_rbac;
CREATE TABLE api_grant_rbac(
   id INTEGER PRIMARY KEY,
   role_id INTEGER NOT NULL,
   api_id INTEGER NOT NULL
);

DROP TABLE if exists sys_config;
CREATE TABLE sys_config (
   id INTEGER PRIMARY KEY,
   config_key TEXT NOT NULL,
   config_value TEXT NOT NULL,
   config_type TEXT NOT NULL
);
INSERT INTO api (id,name,group_id,"path","method","desc",param_mode,sign_validation) VALUES
         (1,'api gateway',1,'/identities/users','post','新增用户',0,0),
         (2,'api gateway',1,'/identities/users/{id}','get','用户查询',0,0),
         (3,'api gateway',1,'/identities/users/{id}','put','修改用户',0,0),
         (4,'api gateway',1,'/identities/users/{id}','delete','删除用户',0,0),
         (5,'api gateway',1,'/identities/users/name/{name}','get','通过用户名查询用户',0,0),
         (6,'api gateway',1,'/identities/users/{id}/groups','get','获取用户与组的关系',0,0),
         (7,'api gateway',1,'/identities/users/{id}/groups','put','修改用户与组的关系',0,0),
         (8,'api gateway',1,'/identities/groups','post','新增用户组',0,0),
         (9,'api gateway',1,'/identities/groups/{id}','get','用户组查询',0,0),
         (10,'api gateway',1,'/identities/groups/{id}','put','修改用户组',0,0);
INSERT INTO api (id,name,group_id,"path","method","desc",param_mode,sign_validation) VALUES
         (11,'api gateway',1,'/identities/groups/{id}','delete','删除用户组',0,0),
         (12,'api gateway',1,'/identities/groups/name/{name}','get','通过组名查询用户组',0,0),
         (13,'api gateway',1,'/identities/groups/{id}/roles','get','获取组与角色的关系',0,0),
         (14,'api gateway',1,'/identities/groups/{id}/roles','put','修改组与角色的关系',0,0),
         (15,'api gateway',1,'/identities/roles','post','新增角色',0,0),
         (16,'api gateway',1,'/identities/roles/{id}','get','角色查询',0,0),
         (17,'api gateway',1,'/identities/roles/{id}','put','修改角色',0,0),
         (18,'api gateway',1,'/identities/roles/{id}','delete','删除角色',0,0),
         (19,'api gateway',1,'/identities/roles/name/{name}','get','通过角色名查询角色',0,0),
         (20,'api gateway',1,'/entities/api_groups','post','新增API Group',0,0);
INSERT INTO api (id,name,group_id,"path","method","desc",param_mode,sign_validation) VALUES
         (21,'api gateway',1,'/entities/api_groups/{id}','get','API Group查询',0,0),
         (22,'api gateway',1,'/entities/api_groups/{id}','put','修改API Group',0,0),
         (23,'api gateway',1,'/entities/api_groups/{id}','delete','删除API Group',0,0),
         (24,'api gateway',1,'/entities/api_groups/name/{name}','get','通过API Group名查询API Group',0,0),
         (25,'api gateway',1,'/entities/api_groups/name/{name}/oas3','post','通过Open API 3.0 格式文档导入API',0,0),
         (26,'api gateway',1,'/entities/api_groups/{id}/apis','get','获取API Group下定义的所有api',0,0),
         (27,'api gateway',1,'/identities/roles/{id}/apis','get','通过 role_id 查询对应role 授权的 API 列表',0,0),
         (28,'api gateway',1,'/identities/roles/{id}/apis','put','通过 role_id 更新对应role 授权的 API 列表',0,0),
         (29,'api gateway',1,'/deploy/app','post','部署已上传的应用',0,0),
         (30,'api gateway',1,'/deploy/app','delete','删除已部署的应用',0,0);
INSERT INTO api (id,name,group_id,"path","method","desc",param_mode,sign_validation) VALUES
         (31,'api gateway',1,'/conf/service','post','注册后端服务',0,0),
         (32,'api gateway',1,'/conf/service','put','更新已注册的后端服务',0,0),
         (33,'api gateway',1,'/conf/service','delete','删除已注册的服务',0,0),
         (34,'api gateway',1,'/conf/upstreams','get','获取所有upstream的配置信息',0,0),
         (35,'api gateway',1,'/conf/smtp','get','获取smtp配置信息',0,0),
         (36,'api gateway',1,'/conf/smtp','post','更新smtp配置信息',0,0),
         (37,'api gateway',1,'/conf/sysconfig/{key}','get','获取系统配置项信息',0,0),
         (38,'api gateway',1,'/conf/sysconfig','post','更新系统配置项信息',0,0),
         (39,'api gateway',1,'/auth/login','post','登录',0,0),
         (40,'api gateway',1,'/auth/verification','post','发送验证码',0,0);
INSERT INTO api_grant_mode (id,api_id,grant_mode) VALUES
         (1,1,1),
         (2,2,1),
         (3,3,1),
         (4,4,1),
         (5,5,1),
         (6,6,1),
         (7,7,1),
         (8,8,1),
         (9,9,1),
         (10,10,1);
INSERT INTO api_grant_mode (id,api_id,grant_mode) VALUES
         (11,11,1),
         (12,12,1),
         (13,13,1),
         (14,14,1),
         (15,15,1),
         (16,16,1),
         (17,17,1),
         (18,18,1),
         (19,19,1),
         (20,20,1);
INSERT INTO api_grant_mode (id,api_id,grant_mode) VALUES
         (21,21,1),
         (22,22,1),
         (23,23,1),
         (24,24,1),
         (25,25,1),
         (26,26,1),
         (27,27,1),
         (28,28,1),
         (29,29,1),
         (30,30,1);
INSERT INTO api_grant_mode (id,api_id,grant_mode) VALUES
         (31,31,1),
         (32,32,1),
         (33,33,1),
         (34,34,1),
         (35,35,1),
         (36,36,1),
         (37,37,1),
         (38,38,1),
         (39,39,0),
         (40,40,0);
INSERT INTO api_grant_rbac(role_id, api_id) select 1, id from api order by id;
INSERT INTO api_group (id,name,base_path,"desc", "user_id") VALUES
         (1,'api_gateway','/api_gateway','API Gateway',1);
INSERT INTO api_role (id,name,"desc") VALUES
         (1,'agw_admin','API Gateway admin ');
INSERT INTO api_user (id,name,password,email,mobile) VALUES
         (1,'agw_admin','S3r0szEkhEQbML9RX9g8U0Ax0cs=',NULL,NULL);
INSERT INTO api_user_group (id,name,"desc") VALUES
         (1,'agw_admin','API Gateway admin group');
INSERT INTO api_user_group_rel (id,user_id,group_id) VALUES
         (1,1,1);
INSERT INTO api_user_group_role_rel (id,group_id,role_id) VALUES
         (1,1,1);
