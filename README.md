NJET介绍
============
NJET应用引擎是面向互联网和云原生应用提供的运行时组态服务程序。具备环境感知、安全控制、加速优化等能力，一般呈现为Web服务、流媒体服务、代理(Proxy)、应用中间件、API网关、消息队列等产品形态。
 
应用引擎在云原生架构中，除了提供南北向通信网关的功能以外，因为提供了服务网格中东西向通信、透明流量劫持、熔断、遥测与故障注入等新功能特性，其地位和作用在云原生架构中变得愈发重要。
NJet最早是基于NGINX1.19基础，fork并独立演进的开源应用引擎，并随着NGINX版本迭代，吸收上游NGINX的更新，已经同步更新到NGINX1.23.1版本。NJet的目标在于适应国内特定的技术规范及标准，如国密算法套件支持，并构建安全可控的云原生数据面，支撑我国云原生产业生态。作为底层引擎，NJet利用动态加载机制可以实现不同的产品形态，如API网关、消息代理、出入向代理，负载均衡，WAF等等


功能特性
========
继承 nginx-1.23.1 所有功能， 并且100%兼容nginx。

支持正向代理，实现支持了HTTP的CONNETC方法。
支持遥测功能（vts\telemetry\log）
支持国密（目前基于天安国密ssl实现，并计划向铜锁迁移）
支持动态http\server\ssl配置功能
支持动态upstream功能
支持主动健康检查功能
声明式api动态配置：
    支持动态黑白名单功能
    支持动态location配置功能
    支持动态access log配置功能
    支持动态telemetry开关功能
    支持动态vts配置功能
    支持动态split_client 功能
    动态（国密）证书更新



安装
============
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

文档
=============
请参考NJET使用手册
