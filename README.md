# OpenNJet

OpenNJet 应用引擎是高性能、轻量级的WEB应用与代理软件。作为云原生服务网格的数据平面，NJet具备动态配置加载、主动式健康检测、集群高可用、声明式API等多种强大功能。通过CoPliot副驾驶服务框架，在隔离控制面和数据面的情况下实现了高可扩展性。NJet应用引擎助力企业实现云原生技术的平滑升级并大幅降低IT运营成本。

<img src="https://gitee.com/gebona/picture/raw/master/202308031418513.png" alt="图片 1" style="zoom:50%;" />

**OpenNJet 是由开放原子开源基金会（OpenAtom Foundation）孵化及运营的开源项目！**

<img src="https://gitee.com/gebona/picture/raw/master/202403151548527.svg" width=40% alt="LOGO" style="zoom:5%;" />

## 独特优势

✨**高性能：**NJet性能是CNCF推荐Envoy的三倍。

✨**功能多：**内置HTTP3、故障注入、遥测、配置动态加载、服务发现等功能

**✨强安全：**集成Web应用防火墙**、**原生支持国密/ RSA加密解密算法

✨**可扩展：**强大的插件框架能力支持第三方应用开发

✨**可编程：**支持LUA、Python可编程控制脚本

**✨易管理：**提供完善的API接口，内置多主集群和高可用性能力

更多功能特性 -> [查看](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E5%8A%9F%E8%83%BD%E7%89%B9%E6%80%A7.md)

## 技术架构

<img src="https://gitee.com/gebona/picture/raw/master/202403151528500.png" alt="图片 1" style="zoom:80%;" />

## 路线图

- [功能规划](https://gitee.com/njet-rd/njet/milestones/190511)

## **快速开始**

  我们提供了几种快速使用的方法：

-    [二进制安装](https://njet.org.cn/docs/quickstart/#1-%E4%BA%8C%E8%BF%9B%E5%88%B6%E5%AE%89%E8%A3%85)
-    [发行版安装](https://njet.org.cn/docs/quickstart/#2-%E5%AE%89%E8%A3%85%E5%8F%91%E8%A1%8C%E7%89%88)
-    [源码安装](https://njet.org.cn/docs/quickstart/#3-%E6%BA%90%E7%A0%81%E5%AE%89%E8%A3%85)
-    [docker镜像启动](https://njet.org.cn/cases/njet-docker/)

#### **镜像构建**

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

**更多详情[查看](https://njet.org.cn/docs/quickstart/)**

## 社区文档

获取更多的信息和使用说明，可以从 [文档](https://gitee.com/njet-rd/docs) 开启OpenNJet的世界！

- [快速上手](https://njet.org.cn/docs/quickstart/)
- [编码规范&新手指引](https://gitee.com/njet-rd/docs/blob/master/zh-cn/OpenNJet%E7%BC%96%E7%A0%81%E8%A7%84%E8%8C%83%E4%BB%A5%E5%8F%8A%E6%96%B0%E6%89%8B%E6%8C%87%E5%BC%95.md)
- [使用手册](https://gitee.com/njet-rd/docs)
- [开发指南](https://gitee.com/njet-rd/docs/blob/master/zh-cn/CoPilot%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97.md)

## 参与贡献

如果您对我们的项目非常感兴趣，请查看 [贡献指南](https://gitee.com/njet-rd/community/blob/master/%E5%BC%80%E5%8F%91%E8%80%85%E8%B4%A1%E7%8C%AE%E6%8C%87%E5%8D%97.md) 了解更多贡献的流程，当然，我们也非常欢迎您通过Issue的方式帮助修正我们的贡献流程。


## 社区交流

- **技术交流面对面：**探讨和分享对 NJet 的建议、使用心得、发展方向等

	QQ群号：607280080

<img src="https://gitee.com/gebona/picture/raw/master/202308031735418.png" alt="WeChat7df7875d28df2f367d1693b20a30762b" style="zoom:25%;" />

- 安全说明

如果您在使用过程中发现任何安全问题，请通过以下方式直接联系我们： 

- 邮箱：lijhaal@tmlake.com

## 许可证

OpenNJet 基于 [MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2/) 许可证！

