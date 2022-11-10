# TASSL-1.1.1k
新版本特性

1、基于开源openssl1.1.1k修改。相较于之前基于openssl1.1.1b版本的tassl，修复了以下漏洞: CVE-2019-1543 CVE-2019-1552 CVE-2019-1563 CVE-2019-1547 CVE-2019-1549 CVE-2020-1967 CVE-2020-1971 CVE-2021-23840 CVE-2021-23839 CVE-2021-23841 CVE-2021-3449 CVE-2021-3450 CVE-2021-3711

2、支持RFC 8998  ShangMi (SM) Cipher Suites for TLS 1.3。基于TLS1.3实现了两个国密套件TLS_SM4_GCM_SM3/TLS_SM4_CCM_SM3。放宽了双证的需求，使用SM2单证书；取消了在使用ECDHE算法时必须有客户端证书的限制。

3、 国密SSL协议(GM/T 0024-2014)改动。不同于旧版本tassl使用定制接口加载加密证书/密钥，新版本使用标准接口加载加密证书/密钥；因此,新版本对于使用openssl的程序有更好的兼容性，降低应用进行国密SSL迁移的开发成本。

4、支持标准版本nginx 。相较于旧版本tassl需要定制nginx以支持国密SSL，新版本tassl可直接与标准nginx实现国密SSL的web server/反向代理；同时支持使用江南天安硬件产品(密码机/密码卡)存储SSL长期密钥，以保证密钥安全性

5、新增支持标准版本apache。新版本tassl可与标准apache实现国密SSL的web server/反向代理；同时支持使用江南天安硬件产品(密码机/密码卡)存储SSL长期密钥，以保证密钥安全性

使用请参考《软算法支持SSL卸载使用指南v1.02(标准nginx).pdf》
