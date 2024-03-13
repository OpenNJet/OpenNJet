# OpenNJet

![Static Badge](https://img.shields.io/badge/License-MulanPSL%202.0-blue)

OpenNJet 应用引擎是基于 NGINX 的面向互联网和**云原生**应用提供的运行时组态服务程序，作为底层引擎，OpenNJet 实现了**NGINX 云原生功能增强、安全加固和代码重构**，利用动态加载机制可以实现不同的产品形态，如Web服务器、流媒体服务器、负载均衡、代理(Proxy)、应用中间件、API网关、消息队列等产品形态等等。OpenNJet 在云原生架构中作为数据平面，除了提供南北向通信网关的功能以外，还提供了服务网格中东西向通信能力。在原有功能基础上增加了透明流量劫持、熔断、遥测与故障注入等新功能特性。

<img src="https://gitee.com/gebona/picture/raw/master/202308031418513.png" alt="图片 1" style="zoom:50%;" />

OpenNJet 最早是基于 NGINX1.19 基础 fork 并独立演进，OpenNJet 具有高性能、稳定、易扩展的特点，同时也解决了 NGINX 长期存在的难于**动态配置**、管理功能影响业务等问题。我们旨在适应国内特定的技术规范及标准，如国密算法套件支持、构建安全可控的云原生数据面，支撑我国云原生产业生态。

**OpenNJet 是由开放原子开源基金会（OpenAtom Foundation）孵化及运营的开源项目！**

# 优势

✨数据面、控制面隔离：CoPilot 框架隔离数据面、管理面功能，避免对数据面能力的影响，在提供稳定高性能的数据面能力的基础上，可以方便地扩充各种管理接口，如指标输出、[健康检查](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8Cv1.1.2.md#36-%E4%B8%BB%E5%8A%A8%E5%81%A5%E5%BA%B7%E6%A3%80%E6%9F%A5)、管理界面、配置同步等；

✨动态能力：动态配置能力可以解决NGINX的长期痛点，实现性能无损的配置变更；

✨内置企业特性：国密、[集群](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8Cv1.1.2.md#323-%E7%BB%84%E6%92%AD%E9%9B%86%E7%BE%A4)状态同步及集群配额控制、[高可用](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8Cv1.1.2.md#323-copilotha)及运维文档一体化。

- 更多功能特性 -> [查看](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E5%8A%9F%E8%83%BD%E7%89%B9%E6%80%A7.md)

# 技术架构

<img src="https://gitee.com/gebona/picture/raw/master/202308031442571.png" alt="image-20230803144159782" style="zoom:50%;" />

- 以不同进程隔离数据面（workers）及控制管理能力（copilots)，两者间主要通过共享内存共享数据；

- 利用 mqtt 协议构建底层 event bus，形成一套动态配置框架，第三方模块容易的实现动态配置改造；
- coworkers 采用插件机制，可以按需和不同的系统对接，实现不同的管控能力；

# 路线图

- [功能规划](https://gitee.com/njet-rd/njet/milestones/190511)

# **快速开始**

  我们提供了几种快速使用的方法：
    二进制安装
    发行版安装
    源码安装
    docker镜像启动

  前三种方式请参考：https://njet.org.cn/docs/quickstart/
  docker镜像启动请参考：https://njet.org.cn/cases/njet-docker/

# **镜像构建**

  如果大家想制作OpenNJet镜像，可使用如下方法：

下载njet_main源码，执行如下命令：
```
  cd njet_main
  //导入环境变量
  export NJET_RIEPOSITORY="tmlake/njet"
  export NJET_TAG="latest"
  //构建镜像
  docker build --build-arg NJet_VERSION=$NJET_TAG --build-arg GIT_COMMIT=$(gitrev-parse HEAD) --network host --target ubuntu-njet -f ./build/docker/Dockerfile_njet -t $NJET_RIEPOSITORY:$NJET_TAG ./
```


# 文档

获取更多的信息和使用说明，可以从 [文档](https://gitee.com/njet-rd/docs) 开启OpenNJet的世界！

- [快速上手](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E5%BF%AB%E9%80%9F%E4%B8%8A%E6%89%8B.md)
- [编码规范&新手指引](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E7%BC%96%E7%A0%81%E8%A7%84%E8%8C%83%E4%BB%A5%E5%8F%8A%E6%96%B0%E6%89%8B%E6%8C%87%E5%BC%95.md)
- [使用手册](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8Cv1.1.2.md)
- [开发指南](https://gitee.com/njet-rd/docs/blob/master/zh-cn/CoPilot%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97.md)

# 贡献

如果您对我们的项目非常感兴趣，请查看 [贡献指南](https://gitee.com/njet-rd/community/blob/master/%E5%BC%80%E5%8F%91%E8%80%85%E8%B4%A1%E7%8C%AE%E6%8C%87%E5%8D%97.md) 了解更多贡献的流程，当然，我们也非常欢迎您通过Issue的方式帮助修正我们的贡献流程。


# 沟通渠道

- 技术交流面对面：QQ群号：607280080

<img src="https://gitee.com/gebona/picture/raw/master/202308031735418.png" alt="WeChat7df7875d28df2f367d1693b20a30762b" style="zoom:25%;" />

- **工作组[会议纪要](http://opennjet.tmlake.com:9011/p/OpenNJet_%E5%8F%8C%E5%91%A8%E4%BC%9A)**

# 安全说明

如果您在使用过程中发现任何安全问题，请通过以下方式直接联系我们： 

- 邮箱：lijhaal@tmlake.com

# 许可证

OpenNJet 基于 [MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2/) 许可证！

