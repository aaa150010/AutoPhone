# gptPhone mac 运行说明

这是一个 macOS 可双击运行的 gptPhone WebUI 工具。主要用途是批量导入邮箱账号，自动走 ChatGPT/OpenAI Auth 授权、邮箱取码、必要时手机接码，并把成功结果上传到 SUB2 分组和 nvtoken 平台。

## 快速启动

拉完代码后进入项目目录：

```sh
cd /Users/lwh/projects/gptPhone
```

第一次运行前建议给启动脚本加执行权限：

```sh
chmod +x 启动_gptPhone.command
```

然后直接双击：

```text
启动_gptPhone.command
```

脚本会自动做这些事：

- 检查并使用 Python 3.13；如果本机有 Homebrew 但没有 Python 3.13，会尝试自动安装 `python@3.13`
- 创建本地虚拟环境 `mac_runtime/.venv`
- 安装 Flask、curl_cffi、cryptography、requests 等依赖
- 准备 `data/`、`engine/` 等运行目录
- 检查 Node.js；如果本机有 Homebrew 但没有 Node.js，会尝试自动安装 `node`
- 启动 WebUI，并自动打开主页面和邮箱管理页

默认地址：

```text
http://127.0.0.1:18777/
http://127.0.0.1:18777/mailboxes
```

如需换端口：

```sh
GPTPHONE_PORT=18788 ./启动_gptPhone.command
```

停止运行：关闭启动脚本打开的 Terminal 窗口，或在 Terminal 里按 `Ctrl-C`。

## mac 双击权限说明

如果双击 `.command` 没反应，或提示没有权限，执行：

```sh
chmod +x 启动_gptPhone.command
```

如果 macOS Gatekeeper 提示来自未知开发者，可以在 Finder 里右键 `启动_gptPhone.command`，选择“打开”，再确认运行。

## 邮箱导入格式

打开邮箱管理页：

```text
http://127.0.0.1:18777/mailboxes
```

每行一个账号，当前常用格式如下。

### 1. 邮箱取件 API

```text
邮箱账号----https://www.example.com/mailbox?token=xxxx
```

系统会识别 `----` 后面是完整 `http/https` URL，并走取件 API 链路。程序会轮询这个 URL，从返回内容里提取 6 位邮箱验证码。

### 2. Outlook OAuth 邮箱

```text
邮箱账号----邮箱密码----client_id----refresh_token
```

系统会走 Outlook OAuth/IMAP 取信链路，用邮箱凭据读取 OpenAI/ChatGPT 发来的邮箱验证码。

### 3. 邮箱密码 / IMAP

```text
邮箱账号----邮箱密码
```

系统会把第二段当作邮箱密码，尝试用 IMAP 读取验证码。`imap_poller.py` 里包含 Outlook/Hotmail、iCloud、Gmail、QQ、163、126 等常见 IMAP 服务器映射。

iCloud 账号通常需要 Apple 的 app-specific password，普通登录密码或“查询码”不能直接作为 IMAP 密码使用。

### 4. 已有 GPT 账号 + 2FA

```text
GPT账号|登录密码|2FA密钥
```

这是 mac override 新增的格式。系统会用账号密码登录，并根据 2FA 密钥本地生成 TOTP 临时验证码。

## 关于手机验证码

手机验证码不是每条邮箱链路都强制需要。

运行时会先完成邮箱/账号登录。如果 OpenAI/ChatGPT 页面没有要求手机验证，流程会直接继续 OAuth callback、token exchange、SUB2 上传和 nvtoken 上传。只有页面进入 `add_phone`、`contact_verification`、`phone_number_collection` 等手机验证状态时，才会调用 SMS 接码平台买号、发短信、等待手机验证码。

## 结果上传

任务成功后会做两类上传：

- **SUB2 上传**：把授权结果上传到配置好的 SUB2 地址和目标分组。
- **nvtoken 上传**：页面里默认勾选“上传到 nvtoken 平台”。成功结果里如果包含 `access_token`、`refresh_token` 和 `email`，系统会额外上传到 nvtoken 的导入接口。

如果不想上传 nvtoken，可以在运行页面取消勾选“上传到 nvtoken 平台”。

## 默认配置

当前 mac 适配层里已经写入了常用默认值：

- SUB2 URL: `http://39.106.173.33:8080/`
- SUB2 账号: `admin@sub2api.local`
- SUB2 分组: `自动化接码分组`
- OpenAI 主代理默认: `http://127.0.0.1:7897`
- SMS 最高价格默认: `0.1`

主代理仍可在页面里修改。SMS、邮箱取码、SUB2 是否走代理由页面上的勾选项控制。

## 常见问题

### 端口被占用

换一个端口启动：

```sh
GPTPHONE_PORT=18788 ./启动_gptPhone.command
```

### 依赖安装失败

确认本机能访问 Python/pip 依赖源，并且安装了 Homebrew。也可以先手动安装：

```sh
brew install python@3.13 node
```

然后重新双击 `启动_gptPhone.command`。

### 邮箱验证码一直收不到

先确认导入格式是否正确：

- `邮箱----https://...` 必须是能返回邮件内容或验证码的完整取件 URL
- `邮箱----密码` 必须是真正可 IMAP 登录的邮箱密码或 app-specific password
- `邮箱----密码----client_id----refresh_token` 的 refresh token 必须仍有效
- `GPT账号|登录密码|2FA密钥` 的 2FA 密钥必须是 Base32 TOTP secret

如果邮箱里已经有旧验证码，系统会先读取基线，再等待新验证码。没有新邮件时会超时。

### iCloud 账号登录失败

iCloud IMAP 服务器是 `imap.mail.me.com:993`，通常不能用普通 Apple ID 密码登录，需要 Apple app-specific password。若看到 `AUTHENTICATIONFAILED`，优先检查 app-specific password 是否正确、账号是否允许邮件客户端访问。

## 项目目录说明

- `启动_gptPhone.command`: mac 双击启动脚本
- `plus_launcher.pyc`: 恢复出的入口字节码
- `business_pyc/`: 选出的业务 `.pyc` 模块
- `mac_overrides/`: mac 适配和 UI/逻辑覆盖层
- `data/`: 运行数据、配置、邮箱池状态
- `engine/`: 运行时准备出的引擎目录
- `external_assets/node_chain.dat`: 原包里的外部数据
- `disassembly/`: 反汇编结果，排查逻辑时参考
- `pycdc_attempt/`: best-effort 反编译结果，只能当提示看
- `tools/recover.py`: 恢复脚本

## 已知限制

当前工具依赖本机 Node.js 来运行 SentinelRunner 相关流程。mac 启动脚本会优先使用本机 `node`，并尝试准备 Node SentinelRunner 目录；如果相关资源不完整，真实授权链路可能会卡在 SentinelRunner 阶段。

另外，项目里的 `.pyc` 是 Python 3.13 字节码。当前常见反编译器对 Python 3.13 支持不完整，所以 `pycdc_attempt/` 不是可直接运行源码，最可靠的逻辑参考是 `disassembly/`。
