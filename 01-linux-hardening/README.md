# 2026-09-25 · Linux 服务器安全巡检报告

> 数据来源：2026-09-24 在本机 Ubuntu 靶机上的实测输出。
> 本日工作：将巡检数据整理成报告结构。

## 一、巡检对象

| 项 | 值 |
|---|---|
| 主机 | Ubuntu 22.04 Desktop（主机名 ubuntu22） |
| 地址 | 192.168.10.137（NAT，VMnet8 `192.168.10.0/24`） |
| 巡检时间 | 2026-09-24 |
| 巡检方式 | 主机内部命令 + 外部 Nmap 7.70 扫描 |

## 二、检查项与结论

### 2.1 账号

| 检查项 | 命令 | 结果 | 风险 |
|---|---|---|---|
| UID=0 账号 | `awk -F: '$3==0 {print $1}' /etc/passwd` | 仅 `root` | 无 |
| 可登录账号 | `grep -v nologin /etc/passwd` | 仅 root 与普通用户；系统账号均为 `/usr/sbin/nologin` | 无 |

结论：未发现非 root 的 UID=0 后门账号；系统账号未开放登录 shell。

### 2.2 认证日志

| 检查项 | 命令 | 结果 | 风险 |
|---|---|---|---|
| 失败登录次数 | `grep -c "Failed password" /var/log/auth.log` | 1（经核实为误报） | 无 |
| 成功登录记录 | `grep "Accepted password" /var/log/auth.log` | 无异常来源 IP | 无 |
| 爆破特征 | 时间集中 + 同源 IP 反复尝试 | 未发现 | 无 |

误报说明：`sudo` 会将自己执行的命令原文写入 `auth.log`，而该命令行本身含
`Failed password` 关键字，导致工具匹配到自身记录。区分方法是看第 4 列的程序名——
`sshd[PID]:` 为真实登录事件，`sudo:` 为提权记账。

结论：未发现 SSH 爆破痕迹；检出 1 条自指误报，已排除。

### 2.3 端口暴露面

内部视图 `ss -tunlp`；外部视图 `nmap -sV 192.168.10.137`

| 检查项 | 结果 | 风险 |
|---|---|---|
| 对外监听端口 | 仅 `22/tcp`（ssh） | 低 |
| 其他监听端口 | 均绑定 `127.0.0.1` / `127.0.0.53`，外部不可达 | 无 |
| 关闭端口 | 999 个，状态均为 `closed` | 无 |
| MAC 厂商 | `00:0C:29:…`（VMware） | 低（暴露虚拟化平台） |

结论：攻击面已收敛至单个 SSH 端口。
判定依据：Nmap 通过 TCP 响应区分状态——回 `SYN-ACK` 为 open，回 `RST` 为 closed，
无响应为 filtered。本次 999 个端口全部 `closed`，说明链路上无防火墙丢包。

### 2.4 SSH 服务版本信息泄露（已整改）

| 项 | 内容 |
|---|---|
| 问题 | banner 回显精确补丁级别，可用于反查 CVE |
| 风险等级 | 低危（信息泄露） |
| 整改前 | `OpenSSH 8.9p1 Ubuntu 3ubuntu0.17 (Ubuntu Linux; protocol 2.0)` |
| 整改动作 | `/etc/ssh/sshd_config` 增加 `DebianBanner no`，`systemctl reload ssh` 生效 |
| 整改后 | `OpenSSH 8.9p1 (protocol 2.0)` |
| 复验方式 | 同一命令 `nmap -sV -p22 <目标 IP>`，对比 VERSION 列 |
| 结论 | 已整改，精确补丁级别不再对外泄露 |

配置生效方式的取舍：`reload` 发送 SIGHUP 重读配置、不断开已有连接；
`restart` 会中断连接，远程执行时可能失去访问。远程环境中一律使用 `reload`。

### 2.5 权限与后门

**SUID 文件排查**

```bash
find / -perm -4000 -type f 2>/dev/null
```

`-perm -4000` 表示权限位至少包含 SUID（4）；`-type f` 只取普通文件。
命中共 32 条，分为四类：

| 类别 | 文件 | 说明 |
|---|---|---|
| 系统标准工具 | `mount` `umount` `su` `sudo` `passwd` `chfn` `chsh` `gpasswd` `newgrp` | 需临时提权完成挂载、切换用户、修改自身密码 |
| 组件自带 | `pkexec` `fusermount3` `Xorg.wrap` `ssh-keysign` `snap-confine` `dbus-daemon-launch-helper` `polkit-agent-helper-1` `pppd` | 各软件包安装时生成 |
| 环境相关 | `/usr/bin/vmware-user-suid-wrapper` | 由 open-vm-tools 安装生成 |
| snap 镜像内副本 | `/snap/core22/1612/…`、`/snap/snapd/21759/…` | snap base 镜像内部副本，非系统路径 |

结论：全部文件均可对应到已知软件包，未发现来路不明的 SUID 文件。
归属校验方式：`dpkg -S <文件路径>`，可回显该文件所属软件包。

**定时任务排查**

```bash
crontab -l                              # 用户级
ls -l /etc/crontab /etc/cron.d/         # 系统级
grep -r . /etc/crontab /etc/cron.d/     # 查看任务内容
```

| 检查项 | 结果 | 风险 |
|---|---|---|
| 用户级任务 | `no crontab for wyy`，当前用户无定时任务 | 无 |
| 文件权限 | `/etc/crontab` 与 `/etc/cron.d/*` 均为 `root:root 644` | 无 |
| 任务内容 | 4 条 `run-parts` 维护任务（hourly/daily/weekly/monthly）、`anacron`（07:30）、`e2scrub_all`（ext4 在线检查）；`.placeholder` 为 dpkg 占位文件，非任务 | 无 |

结论：全部任务以 `root` 身份执行，均为系统自带脚本，未发现自定义命令或外部拉取。

注：系统级 crontab（`/etc/crontab`、`/etc/cron.d/`）比用户级多一个 user-name 字段，
格式为 `分 时 日 月 周 用户 命令`，用于指定执行身份。

**排查纪律（记录）**

使用 `2>/dev/null` 屏蔽错误输出时，命令自身的参数错误也会被一并屏蔽，屏幕空白
并不等于结果为空。校验方式是先看是否有输出，再检查退出码 `echo $?`：有输出则结果
可用；无输出且退出码非 0 表示命令执行失败，结果不可用。


## 三、整改建议

- SSH 访问收敛：`PermitRootLogin no`、`PasswordAuthentication no`（改密钥登录）、
   防火墙仅放行指定来源 IP、部署 fail2ban 自动封禁爆破源。


## 环境
- GitHub: github.com/Wu-yunyan
