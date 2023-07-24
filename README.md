

# **OpenNJet 介绍**

OpenNJet 应用引擎是基于 NGINX 的面向互联网和云原生应用提供的运行时组态服务程序。具备环境感知、安全控制、加速优化等能力，作为底层引擎，OpenNJet 利用动态加载机制可以实现不同的产品形态，如API网关、消息代理、出入向代理，负载均衡，WAF等等。在云原生架构中，OpenNJet 除了提供南北向通信网关的功能以外，还提供了服务网格中东西向通信、透明流量劫持、熔断、遥测与故障注入等新功能特性。 

OpenNJet 最早是基于 NGINX1.19 基础 fork 并独立演进，随着 NGINX 版本迭代，吸收上游 NGINX 的更新，已经同步更新到 NGINX1.23.1 版本，OpenNJet 具有高性能、稳定、易扩展的特点，同时也解决了 NGINX 长期存在的难于动态配置、管理功能影响业务等问题。我们目标在于适应国内特定的技术规范及标准，如国密算法套件支持、构建安全可控的云原生数据面，支撑我国云原生产业生态。



# 🏗️ 技术架构

![teck-arch](https://gitee.com/gebona/picture/raw/master/202307051059921.png)

# ✨ **功能特性**   

[OpenNJet功能特性](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E5%8A%9F%E8%83%BD%E7%89%B9%E6%80%A7.md)


# 💥源码下载

OpenNJet 主库地址：

https://gitee.com/njet-rd/njet



# 🚀**安装**

**Quic Start:**

   提供基于 Dockerfile 文件的形式进行快速编译

**依赖：**

1. docker 环境（需要在编译机器安装docker并启动docker）

**步骤：**  

1. 下载 OpenNJet 源码
2. 执行如下命令：

​     docker build -t njet_main:v1.0 .

​     docker run -v &#96;pwd&#96;:/njet_main njet_main:v1.0 /bin/bash -c "cd /njet_main && sh build_njet.sh"

3. 编译完后，在 objs 目录下，主要包含 njet 文件和相关的 so 文件

​     njet 可执行文件

​     *.so 相关模块对应的动态库文件



# 📝**文档**

[OpenNJet快速上手](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E5%BF%AB%E9%80%9F%E4%B8%8A%E6%89%8B.md)

[OpenNJet编码规范以及新手指引](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E7%BC%96%E7%A0%81%E8%A7%84%E8%8C%83%E4%BB%A5%E5%8F%8A%E6%96%B0%E6%89%8B%E6%8C%87%E5%BC%95.md)

[OpenNJet遗留问题](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E9%81%97%E7%95%99%E9%97%AE%E9%A2%98.md)

[OpenNJet使用手册v1.0](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8C.md)

[OpenNJet使用手册v1.1.1](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8Cv1.1.1.md)

[OpenNJet使用手册v1.1.2](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8Cv1.1.2.md)



# 📝**其他资料**
[云原生应用引擎技术发展白皮书](云原生应用引擎技术发展白皮书.pdf) 


# FAQ

### 什么是应用引擎？

---

应用引擎是面向互联网和云原生应用提供的运行时组态服务程序。具备环境感知、安全控制、加速优化等能力，一般呈现为Web服务、流媒体服务、代理(Proxy)、应用中间件、API网关、消息队列等产品形态。

- 互联网时代国际主流的应用引擎包括：NGINX, Apache, IIS 等。

- 在云原生时代有许多新的轻量级应用引擎涌现，比较流行的云原生应用引擎包括： NGINX(C语言 ) ，Envoy(C++语言) , Linkerd(Rust语言) 等。

在云原生架构中，应用引擎除了提供南北向通信网关的功能以外，还提供了服务网格中东西向通信、透明流量劫持、熔断、遥测与故障注入、链路追踪、蓝绿发布等新功能特性，因此应用引擎在云原生架构中发挥着更为关键的作用。

![app](https://gitee.com/gebona/picture/raw/master/202307051100792.png)

<center>图1 云原生应用引擎架构

#### 应用引擎的产品形态

![product](https://gitee.com/gebona/picture/raw/master/202307051101908.png)

<center>图2 应用引擎产品形态

如上图所示，应用引擎产品形态包括Web服务器、流媒体服务器、应用服务器和代理服务器等。其中代理服务器又可分为正向代理、反向代理、边车和消息代理等产品。




# 技术交流QQ群：

群号：607280080

<img src="https://gitee.com/gebona/picture/raw/master/202307051101964.jpg" alt="qq" style="zoom:50%;" />
