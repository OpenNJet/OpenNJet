

# **OpenNJet 介绍**

OpenNJet 应用引擎是基于 NGINX 的面向互联网和云原生应用提供的运行时组态服务程序。具备环境感知、安全控制、加速优化等能力，作为底层引擎，OpenNJet 利用动态加载机制可以实现不同的产品形态，如API网关、消息代理、出入向代理，负载均衡，WAF等等。在云原生架构中，OpenNJet 除了提供南北向通信网关的功能以外，还提供了服务网格中东西向通信、透明流量劫持、熔断、遥测与故障注入等新功能特性。 

OpenNJet 最早是基于 NGINX1.19 基础 fork 并独立演进，随着 NGINX 版本迭代，吸收上游 NGINX 的更新，已经同步更新到 NGINX1.23.1 版本，OpenNJet 具有高性能、稳定、易扩展的特点，同时也解决了 NGINX 长期存在的难于动态配置、管理功能影响业务等问题。我们目标在于适应国内特定的技术规范及标准，如国密算法套件支持、构建安全可控的云原生数据面，支撑我国云原生产业生态。



# 🏗️ 技术架构

![teck-arch](img/teck-arch.png)



# ✨ **功能特性**   



<center><table class="MsoNormalTable" border="0" cellspacing="0" cellpadding="0" width="525" style="width:394.0pt;border-collapse:collapse;mso-yfti-tbllook:1184;
 mso-padding-alt:0cm 5.4pt 0cm 5.4pt">
 <tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;height:16.0pt">
  <td width="525" nowrap="" colspan="2" style="width:394.0pt;border:solid windowtext 1.0pt;
  mso-border-alt:solid windowtext .5pt;padding:0cm 5.4pt 0cm 5.4pt;height:16.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><b><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">继承<span lang="EN-US"> nginx-1.23.1 </span>所有功能， 并且<span lang="EN-US">100%</span>兼容<span class="SpellE"><span lang="EN-US">nginx</span></span><span lang="EN-US"><o:p></o:p></span></span></b></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:1;height:16.0pt">
  <td width="525" nowrap="" colspan="2" style="width:394.0pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-top-alt:solid windowtext .5pt;mso-border-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:16.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span class="SpellE"><b><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">OpenNJet</span></b></span><b><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt"> </span></b><b><span style="font-size:12.0pt;
  mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:
  DengXian;mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">功能特性<span lang="EN-US"><o:p></o:p></span></span></b></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:2;height:17.0pt">
  <td width="203" nowrap="" rowspan="2" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">Copilot</span><span style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">框架<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持动态加载不同的外部<span lang="EN-US">copilot</span>模块<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:3;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持外部模块异常退出的自动重启<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:4;height:17.0pt">
  <td width="203" nowrap="" rowspan="2" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">KV</span><span style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">模块<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持键值的查询及设置<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:5;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持键值的持久化<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:6;height:17.0pt">
  <td width="203" nowrap="" rowspan="3" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">动态配置框架<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持控制平面的消息发送<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:7;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">RPC</span>消息、组播消息<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:8;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持消息持久化<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:9;height:17.0pt">
  <td width="203" nowrap="" rowspan="3" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">Cache-purge<o:p></o:p></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持缓存清理<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:10;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持按指定前缀清理缓存<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:11;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">开启分片后修改源文件不会造成下载失败<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:12;height:34.0pt">
  <td width="203" nowrap="" rowspan="7" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span class="SpellE"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">health_check</span></span><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt"><o:p></o:p></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持单独在<span lang="EN-US">helper</span>进程开启健康检查，不影响数据面业务<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:13;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行时动态开启或关闭健康检查功能<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:14;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持校验返回<span lang="EN-US">http code<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:15;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持校验返回<span lang="EN-US">http header<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:16;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持校验返回<span lang="EN-US">http body<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:17;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">https</span>健康检查<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:17;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持强制健康检查，以及持久化功能<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:18;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持国密<span lang="EN-US">https</span>健康检查<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:19;height:17.0pt">
  <td width="203" nowrap="" rowspan="2" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">Split-clients-2<o:p></o:p></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持蓝绿发布<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:20;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行时动态调整流量比例<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:21;height:17.0pt">
  <td width="203" nowrap="" rowspan="3" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">黑白名单<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持黑名单方式进行访问<span lang="EN-US">IP</span>的限制<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:22;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持白名单方式进行访问<span lang="EN-US">IP</span>的限制<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:23;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt"><span style="mso-spacerun:yes">&nbsp;</span></span><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行时动态设置<span lang="EN-US">IPv4</span>的黑白名单列表 <span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:24;height:34.0pt">
  <td width="203" nowrap="" rowspan="3" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">doc</span><span style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">模块<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">location </span>级别通过<span class="SpellE"><span lang="EN-US">doc_api</span></span><span lang="EN-US"> </span>指令配置，实现对<span lang="EN-US">swagger</span>、<span class="SpellE"><span lang="EN-US">gui</span></span>页面的访问<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:25;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span lang="EN-US">swagger </span>页面实现对各功能<span class="SpellE"><span lang="EN-US">opentapi</span></span>的访问<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:26;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span class="SpellE"><span lang="EN-US">gui</span></span>页面实现对动态模块配置修改的能力<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:27;height:17.0pt">
  <td width="203" nowrap="" rowspan="2" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">telemetry</span><span style="font-size:12.0pt;
  mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:
  DengXian;mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">（外部编译模块）<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">http</span>请求在不同<span lang="EN-US">server</span>间的服务追踪<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:28;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持动态开关控制调用链的生成<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:29;height:34.0pt">
  <td width="203" nowrap="" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">正向代理（支持<span lang="EN-US">http/https</span>）<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">实现了<span lang="EN-US">HTTP CONNECT </span>方法支持<span lang="EN-US">http/https</span>正向代理访问<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:30;height:85.0pt">
  <td width="203" nowrap="" rowspan="5" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:85.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span class="SpellE"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">vts</span></span><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">模块<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:85.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">server</span>的<span lang="EN-US">request</span>、<span lang="EN-US">response</span>、<span lang="EN-US">traffic</span>、<span lang="EN-US">cache</span>信息的统计，其中<span lang="EN-US">server</span>的<span lang="EN-US">response</span>可以按照<span lang="EN-US">response code</span>进行分类统计，分类统计使用的<span lang="EN-US">response code</span>为<span lang="EN-US">1xx</span>、<span lang="EN-US">2xx</span>、<span lang="EN-US">3xx</span>、<span lang="EN-US">4xx</span>、<span lang="EN-US">5xx<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:31;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">upstream</span>和<span lang="EN-US">cache</span>信息的统计<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:32;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过内嵌的<span lang="EN-US">html</span>页面进行统计信息的展示<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:33;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span lang="EN-US">Prometheus</span>、<span class="SpellE"><span lang="EN-US">grafana</span></span>进行统计信息的展示<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:34;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持动态配置<span lang="EN-US">server</span>的<span lang="EN-US">location</span>统计开关，支持动态配置<span lang="EN-US">server</span>的<span lang="EN-US">filter key<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:35;height:17.0pt">
  <td width="203" nowrap="" rowspan="4" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">国密支持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">server</span>中使用国密<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:36;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持反向代理中使用国密<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:37;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持国密双证证书<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:38;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">动态（国密）证书更新<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:39;height:17.0pt">
  <td width="203" nowrap="" rowspan="6" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">动态<span lang="EN-US">access log<o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行中动态关闭<span lang="EN-US">access log</span>功能<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:40;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行中动态修改写入的日志文件<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:41;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行中切换<span lang="EN-US">syslog</span>服务器<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:42;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行中切换写入文件的变量<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:43;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行时增加日志<span lang="EN-US">format<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:44;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持运行时修改日志<span lang="EN-US">format<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:45;height:17.0pt">
  <td width="203" nowrap="" rowspan="3" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">声明式<span lang="EN-US">API<o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持感知声明式模块注册<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:46;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持查询声明式模块查询<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:47;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">PUT</span>方式更新声明式配置<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:48;height:17.0pt">
  <td width="203" nowrap="" rowspan="4" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">边车支持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持流量劫持，兼容<span class="SpellE"><span lang="EN-US">istio</span></span><span lang="EN-US"> </span>规则<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:49;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持协议识别<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:50;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持代理<span lang="EN-US">http1.1<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:51;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US"> <span class="SpellE">istio</span> </span>的双向认证<span lang="EN-US">(service-to-service <span class="SpellE">mTLS</span>)<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:52;height:17.0pt">
  <td width="203" nowrap="" rowspan="2" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">动态<span lang="EN-US">location </span>支持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span class="SpellE"><span lang="EN-US">api</span></span><span lang="EN-US"> </span>向<span lang="EN-US">vs </span>添加<span lang="EN-US"> location<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:53;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span class="SpellE"><span lang="EN-US">api</span></span><span lang="EN-US"> </span>从<span lang="EN-US">vs</span>中删除已经添加的<span lang="EN-US">location<o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:54;height:34.0pt">
  <td width="203" nowrap="" rowspan="4" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">动态<span lang="EN-US">upstream <span class="SpellE">api</span>
  </span>支持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span class="SpellE"><span lang="EN-US">api</span></span>，对<span lang="EN-US">http </span>或<span lang="EN-US">stream </span>中的<span lang="EN-US">upstream
  </span>信息进行查询<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:55;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span class="SpellE"><span lang="EN-US">api</span></span>，对<span lang="EN-US">http </span>或<span lang="EN-US">stream </span>中的<span lang="EN-US">upstream
  </span>的<span lang="EN-US">server </span>进行， 添加，修改，删除<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:56;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span class="SpellE"><span lang="EN-US">api</span></span>，对<span lang="EN-US">http </span>或<span lang="EN-US">stream </span>中的<span lang="EN-US">upstream
  </span>的统计信息进行重置<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:57;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">post </span>添加的<span lang="EN-US">upstream
  server </span>持久化或非持久化 <span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:58;height:51.0pt">
  <td width="203" nowrap="" rowspan="2" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:51.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">动态域名<span lang="EN-US">upstream server<o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:51.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持静态配置<span lang="EN-US">upstream server </span>域名的<span class="SpellE"><span lang="EN-US">reslove</span></span><span lang="EN-US"> </span>属性，定时解析域名，根据域名对应的<span class="SpellE"><span lang="EN-US">ip</span></span><span lang="EN-US"> </span>增减结果，同步更新到<span lang="EN-US">upstream server </span>列表中<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:59;height:34.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:34.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持通过<span lang="EN-US">upstream <span class="SpellE">api</span>
  post</span>接口，添加<span lang="EN-US">server </span>域名，并定时解析域名<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:60;height:17.0pt">
  <td width="203" rowspan="3" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span lang="EN-US" style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">Http </span><span style="font-size:12.0pt;mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;
  mso-bidi-font-family:宋体;color:black;mso-font-kerning:0pt">会话保持支持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">cookie </span>会话保持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:61;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span lang="EN-US">route </span>会话保持<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:62;mso-yfti-lastrow:yes;height:17.0pt">
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">支持<span class="SpellE"><span lang="EN-US">lear</span></span><span lang="EN-US"> </span>会话保持 <span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
 <tr style="mso-yfti-irow:60;height:17.0pt">
  <td width="203" nowrap="" rowspan="4" style="width:152.15pt;border:solid windowtext 1.0pt;
  border-top:none;mso-border-left-alt:solid windowtext .5pt;mso-border-bottom-alt:
  solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;padding:
  0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="center" style="text-align:center;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt">负载均衡<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
  <td width="322" style="width:241.85pt;border-top:none;border-left:none;
  border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;
  mso-border-bottom-alt:solid windowtext .5pt;mso-border-right-alt:solid windowtext .5pt;
  padding:0cm 5.4pt 0cm 5.4pt;height:17.0pt">
  <p class="MsoNormal" align="left" style="text-align:left;mso-pagination:widow-orphan"><span style="font-size:12.0pt;mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:宋体;color:black;
  mso-font-kerning:0pt"><span lang="EN-US">slow_start </span>慢启动功能,针对轮询算法，实现<span lang="EN-US">server</span>新增或故障转正常后，业务的流量在指定时间，缓慢增长<span lang="EN-US"><o:p></o:p></span></span></p>
  </td>
 </tr>
</tbody></table>



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

​     docker run -v `pwd`:/njet_main njet_main:v1.0 /bin/bash -c "cd /njet_main && sh build_njet.sh"

3. 编译完后，在 objs 目录下，主要包含 njet 文件和相关的 so 文件

​     njet 可执行文件

​     *.so 相关模块对应的动态库文件



# 📝**文档**

[OpenNJet使用手册](OpenNJet使用手册.pdf)  
[OpenNJet快速上手](OpenNJet快速上手.pdf)  
[OpenNJet遗留问题](OpenNJet遗留问题.pdf)


# 📝**其他资料**
[云原生应用引擎技术发展白皮书](云原生应用引擎技术发展白皮书.pdf) 


# FAQ

### 什么是应用引擎？

---

应用引擎是面向互联网和云原生应用提供的运行时组态服务程序。具备环境感知、安全控制、加速优化等能力，一般呈现为Web服务、流媒体服务、代理(Proxy)、应用中间件、API网关、消息队列等产品形态。

- 互联网时代国际主流的应用引擎包括：NGINX, Apache, IIS 等。

- 在云原生时代有许多新的轻量级应用引擎涌现，比较流行的云原生应用引擎包括： NGINX(C语言 ) ，Envoy(C++语言) , Linkerd(Rust语言) 等。

在云原生架构中，应用引擎除了提供南北向通信网关的功能以外，还提供了服务网格中东西向通信、透明流量劫持、熔断、遥测与故障注入、链路追踪、蓝绿发布等新功能特性，因此应用引擎在云原生架构中发挥着更为关键的作用。

![app](img/app.png)

<center>图1 云原生应用引擎架构

#### 应用引擎的产品形态

![product](img/product.png)

<center>图2 应用引擎产品形态

如上图所示，应用引擎产品形态包括Web服务器、流媒体服务器、应用服务器和代理服务器等。其中代理服务器又可分为正向代理、反向代理、边车和消息代理等产品。




# 技术交流QQ群：

群号：607280080

![qq](img/qq.jpg)
