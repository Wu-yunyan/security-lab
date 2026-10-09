# security-lab

一台本地 Ubuntu 虚拟机上的安全实践记录。两个项目都是自己从零搭靶场、自己动手打、把过程和数据写成报告。

**环境**：VMware 17 Pro（2C4G / NAT）｜ Ubuntu 22.04 ｜ Apache 2.4.52 ｜ PHP 8.1 ｜ MariaDB 10.6.23
**靶场**：DVWA（Damn Vulnerable Web Application）

## 项目

| 目录 | 内容 | 时间 |
|---|---|---|
| [01-linux-hardening](./01-linux-hardening/) | Linux 服务器安全巡检：账号与口令、文件权限、服务与端口、日志排查、定时任务 | 2026.09.24 |
| [02-dvwa-vuln-report](./02-dvwa-vuln-report/) | DVWA 漏洞复现：SQL 注入、XSS（反射型 / 存储型）、文件上传 getshell | 2026.09.26 – 09.28 |

## 做了什么

**巡检**：按等保三级「身份鉴别 / 访问控制 / 安全审计 / 入侵防范 / 数据完整性」五类逐条核对，输出不符合项。本机结论：`auditd` 未运行、`ufw` 未启用（安全审计与边界防护两项不符）；无空口令账号、`/etc` 权限未放开、`/etc/cron.d` 内任务均可对应到所属软件包。

**漏洞复现**：三个漏洞各按 low / medium / high 档读源码对比，记录 payload、服务器回显与日志佐证。

- SQL 注入：`mysqli_real_escape_string` 只处理引号，medium 档改用 `str_replace` 过滤，均可绕过
- XSS：`xss_r` 只进 HTML、`xss_s` 同时进 SQL 与 HTML；转义按语境选择，输出编码才是有效修复
- 文件上传：low 档零校验直接 getshell（`uid=33(www-data)`），medium 档只校验客户端自报的 Content-Type，改一个字段即可绕过

复现结束后均已清理上传的样本文件并复查 404。
