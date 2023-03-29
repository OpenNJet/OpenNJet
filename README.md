NJET介绍
============
NJET应用引擎是面向互联网和云原生应用提供的运行时组态服务程序。具备环境感知、安全控制、加速优化等能力，一般呈现为Web服务、流媒体服务、代理(Proxy)、应用中间件、API网关、消息队列等产品形态。
 
应用引擎在云原生架构中，除了提供南北向通信网关的功能以外，因为提供了服务网格中东西向通信、透明流量劫持、熔断、遥测与故障注入等新功能特性，其地位和作用在云原生架构中变得愈发重要。
NJet最早是基于NGINX1.19基础，fork并独立演进的开源应用引擎，并随着NGINX版本迭代，吸收上游NGINX的更新，已经同步更新到NGINX1.23.1版本。NJet的目标在于适应国内特定的技术规范及标准，如国密算法套件支持，并构建安全可控的云原生数据面，支撑我国云原生产业生态。作为底层引擎，NJet利用动态加载机制可以实现不同的产品形态，如API网关、消息代理、出入向代理，负载均衡，WAF等等


功能特性
========
```
继承 nginx-1.23.1 所有功能， 并且100%兼容nginx。

Copilot框架
   支持动态加载不同的外部copilot模块
   支持外部模块异常退出的自动重启

KV模块
  支持键值的查询及设置
  支持键值的持久化

动态配置框架
  支持控制平面的消息发送
  支持RPC消息、组播消息
  支持消息持久化

Cache-purge
  支持缓存清理
  支持按指定前缀清理缓存
  开启分片后修改源文件不会造成下载失败

health_check
  支持单独在helper进程开启健康检查，不影响数据面业务
  支持运行时动态开启或关闭健康检查功能
  支持校验返回http code
  支持校验返回http header
  支持校验返回http body
  支持https健康检查
  支持国密https健康检查

Split-clients-2
  支持蓝绿发布
  支持运行时动态调整流量比例

黑白名单
  支持黑名单方式进行访问IP的限制
  支持白名单方式进行访问IP的限制
  支持运行时动态设置IPv4的黑白名单列表 

doc模块
  支持location 级别通过doc_api 指令配置，实现对swagger、gui页面的访问
  支持通过swagger 页面实现对各功能opentapi的访问
  支持通过gui页面实现对动态模块配置修改的能力

telemetry（外部编译模块）
  支持http请求在不同server间的服务追踪
  支持动态开关控制调用链的生成

正向代理（支持http/https）
  实现了HTTP CONNECT 方法支持http/https正向代理访问

vts模块
  支持server的request、response、traffic、cache信息的统计，其中server的response可以按照response code进行分类统计，分类统计使用的response code为1xx、2xx、3xx、4xx、5xx；
  支持upstream和cache信息的统计；
  支持通过内嵌的html页面进行统计信息的展示；
  支持通过Prometheus、grafana进行统计信息的展示；
  支持动态配置server的location统计开关，支持动态配置server的filter key；

国密支持
  支持server中使用国密；
  支持反向代理中使用国密；
  支持国密双证证书；
  动态（国密）证书更新

动态access log
  支持运行中动态关闭access log功能
  支持运行中动态修改写入的日志文件
  支持运行中切换syslog服务器
  支持运行中切换写入文件的变量
  支持运行时增加日志format
  支持运行时修改日志format

声明式API
  支持感知声明式模块注册
  支持查询声明式模块查询
  支持PUT方式更新声明式配置

边车支持
  支持流量劫持，兼容istio 规则
  支持协议识别
  支持代理http1.1
  支持 istio 的双向认证(service-to-service mTLS)

动态location 支持
  支持通过api 向vs 添加 location
  支持通过api 从vs中删除已经添加的location

动态upstream api 支持
  支持通过api，对http 或stream 中的upstream 信息进行查询
  支持通过api，对http 或stream 中的upstream 的server 进行， 添加，修改，删除
  支持通过api，对http 或stream 中的upstream 的统计信息进行重置
  支持post 添加的upstream server 持久化或非持久化 

动态域名upstream server
  支持静态配置upstream server 域名的reslove 属性，定时解析域名，根据域名对应的ip 增减结果，同步更新到upstream server 列表中
  支持通过upstream api  post接口，添加server 域名，并定时解析域名。

Http 会话保持支持
  支持cookie 会话保持
  支持route 会话保持
  支持lear 会话保持  

```


安装
============
```
quic start:
     提供基于Dockerfile文件的形式进行快速编译
依赖：
     1. docker 环境（需要在编译机器安装docker并启动docker）
步骤：    
     1. 下载NJET源码
     2. 执行如下命令：
          docker build -t njet_main:v1.0 .
          docker run -v `pwd`:/njet_main njet_main:v1.0 /bin/bash -c "cd /njet_main && sh build_njet.sh"
     3. 编译完后，在objs目录下，主要包含njet文件和相关的so文件
          njet 可执行文件
          *.so 相关模块对应的动态库文件

```

文档
=============
请参考NJET使用手册
