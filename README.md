# 自动接码机（gptPhone）macOS 使用说明

这是一个 macOS 可双击运行的 Element Plus WebUI 工具。主要用途是批量导入邮箱账号，自动走 ChatGPT/OpenAI Auth 授权、邮箱取码、必要时手机接码，并把成功结果上传到 SUB2 分组和 nvtoken 平台。

## 快速启动

拉完代码后进入项目目录：

```sh
cd /Users/lwh/projects/gptPhone
```

第一次运行前建议给启动脚本加执行权限：

```sh
chmod +x start.command
```

然后直接双击：

```text
start.command
```

脚本会自动做这些事：

- 检查并使用 Python 3.13；如果本机有 Homebrew 但没有 Python 3.13，会尝试自动安装 `python@3.13`
- 创建本地虚拟环境 `mac_runtime/.venv`
- 安装 Flask、curl_cffi、cryptography、requests 等依赖
- 准备 `data/`、`engine/` 等运行目录
- 检查 Node.js；如果本机有 Homebrew 但没有 Node.js，会尝试自动安装 `node`
- 启动 WebUI，并自动打开“自动接码机”主页面

默认地址：

```text
http://127.0.0.1:18777/
http://127.0.0.1:18777/mailboxes
```

端口固定为 `18777`。如果重复双击启动，脚本会先关闭旧的 WebUI 实例，再在同一端口启动新的。

主页面左侧提供“运行控制”和“邮箱管理”两个入口，不需要同时打开两个浏览器标签页。

停止运行：关闭启动脚本打开的 Terminal 窗口，或在 Terminal 里按 `Ctrl-C`。

## mac 双击权限说明

如果双击 `.command` 没反应，或提示没有权限，执行：

```sh
chmod +x start.command
```

如果 macOS Gatekeeper 提示来自未知开发者，可以在 Finder 里右键 `start.command`，选择“打开”，再确认运行。

## 页面使用流程

### 1. 导入邮箱

打开左侧“邮箱管理”，在“批量追加导入”文本框中每行粘贴一个账号，然后点击标题右侧的“追加导入”。导入会追加到现有邮箱池，完全重复的行会自动跳过。

邮箱表格支持：

- 搜索邮箱、密码和状态
- 按状态筛选和分页
- 点击邮箱或密码复制
- 单行“查码”，验证码显示在对应行
- 勾选后恢复为可用状态或删除
- 查看成功任务的接码成本；悬浮金额可查看美元报价、USD/CNY 汇率和汇率日期
- 实时查看每个运行中邮箱所在的业务节点和已停留秒数

表格“状态”列表示邮箱池当前状态：`可用`、`运行中`、`已使用`或`失败`。邮箱关联任务运行时会实时切换为“运行中”；旁边的“运行状态”列显示“OAuth 创建节点”“正在获取手机号”“等待短信验证码”等具体节点。任务结束后，“状态”回到最终池状态，“运行状态”保留并冻结在最后一个有效节点。

### 2. 填写运行配置

打开左侧“运行控制”，按需填写：

- 代理地址及 SMS、邮箱取码、SUB2 的代理开关
- 目标数量、并发数、Node 并发数和 Node 超时
- SMSBower 最低/最高价格、短信超时、手机阶段超时、每号最大尝试和一个或多个 API Key
- 鉴权额外重试次数；`0` 表示失败后不额外重试，默认 `1`
- SUB2 地址、账号、管理密码和分组
- 是否上传 nvtoken，以及 nvtoken 导入地址和 API Key

“每号最大尝试”默认和上限都是 `10`，手机阶段超时默认和上限都是 `480` 秒。旧配置第一次加载时会迁移到这组受限默认值，避免异常线路无限消耗号码。

管理密码、SMS API Key 和 nvtoken API Key 都使用 Element Plus 原生密码输入框，点击输入框右侧眼睛可以显示或隐藏当前内容。SMS Key 编辑器右侧的加号可新增一行，每行独立显示和删除，至少保留一个可填写行。保存时会去除空行、首尾空格和重复 Key，并保留原顺序。

### 3. 保存、预检和运行

运行配置下方的操作栏始终保持单行，依次为：

1. **导入配置**：读取本机 JSON，兼容新版 Key 数组和旧版单 Key。
2. **导出配置**：下载包含完整敏感信息的 JSON。
3. **保存配置**：保存当前页面设置。
4. **真实链路预检**：检查所有 SMS Key 余额、SMS 报价、SUB2、Node 链路等条件，不启动批量任务。
5. **开始运行**：使用当前邮箱池启动任务。
6. **停止**：向正在运行的任务发送安全停止请求。

建议第一次配置或修改 SUB2/代理后，先保存配置，再执行一次真实链路预检，预检通过后开始运行。

右侧“任务结果”和“运行日志”分别独立滚动。任务运行期间可以持续查看状态，不会带动整个页面滚动。

运行统计第一行保留状态、邮箱可用总数、成功数量和失败数量；第二行按排队等待、OAuth 节点、邮箱验证、获取手机号、短信接码、收尾上传六组汇总当前未结束任务。任务结果表的“运行状态”按秒更新，失败或停止后保留最后业务节点并冻结计时。

`/api/state` 的任务项会返回 `progress.code`、`progress.label`、`progress.group`、`progress.entered_at` 和 `progress.finished_at`，`runtime.stage_counts` 固定返回上述六组计数。这些字段只包含节点名称和时间，不包含邮箱密码、手机号、SMS Key、Token 或底层链路事件详情。

### 4. 导入和导出配置

“导入配置”和“导出配置”用于迁移本机保存的 SMS、SUB2 和 nvtoken 配置。新版 JSON 使用 `sms_api_keys: string[]`；旧文件里的 `sms_api_key` 会自动变成一行，不会按 `-` 拆分。导出的 JSON 包含完整敏感信息，应仅保存在可信设备上，不要提交到 Git 或发送给他人。

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

### 多 SMS Key 与余额

预检会逐个查询 SMSBower Key 的美元余额，并在当前最低/最高价格范围内查找最低可用报价。每行 Key 会显示“可用 $1.25”“余额不足 $0.00”“Key 无效”或网络/限流状态。

- 部分 Key 余额不足或不可用时，页面会列出 Key 序号，其余 Key 仍可运行。
- 所有 Key 都余额不足时，预检失败并阻止启动。
- 运行中单个 Key 耗尽时，只停用该 Key，后续订单切换到其他 Key。
- 所有 Key 都耗尽时，不再创建新短信订单；已经领取的号码仍会处理完成，后续需要号码的任务会得到 `sms_balance_insufficient`。
- 号码从哪个 Key 领取，后续查码、完成和取消就固定使用同一个 Key。日志和状态只记录 SHA-256 短指纹，不记录原始 Key。

多 Key 池按“最少占用 + 轮询”分配。相同 Key 的相同余额告警每次运行只显示一次，避免状态轮询重复弹窗。

### 并发与重试策略

- 批量任务并发和 Node 并发默认都是 `5`。
- 手机号提交全局最多并发 `2`，相邻提交至少间隔 `750ms`。
- 未验证线路同时使用 `1` 个号码；已有成功记录的线路最多并发 `2`。
- OpenAI 临时服务错误复用同一个号码，并按 `2/4/8` 秒退避重试。
- 已使用号码线路冷却 `10` 分钟，可疑相似号码线路冷却 `30` 分钟，连续两次没有验证码的线路冷却 `5` 分钟。
- 每个任务最多尝试 `10` 个号码，手机阶段最多运行 `480` 秒。

这些限制只约束手机号阶段，不会把整个任务并发强制降到 `2`。

### 接码成本

收到短信验证码后，该激活订单的美元报价会计入任务；没有收到验证码的订单保留脱敏结果明细，但不计入成功接码成本。任务结果保存：

- `sms_cost_usd`：有效激活订单的美元合计
- `sms_cost_cny`：换算后的人民币金额
- `sms_exchange_rate`、`sms_exchange_date`：换算汇率和日期
- `sms_order_outcomes`：不含原始激活 ID 和 Key 的订单明细

USD/CNY 每 24 小时从 ECB 日汇率推导一次。网络失败时先使用上次缓存，没有缓存时回退到 `7.20`。历史结果没有成本字段时，邮箱表格显示“暂无”。

## 结果上传

任务成功后会做两类上传：

- **SUB2 上传**：把授权结果上传到配置好的 SUB2 地址和目标分组。
- **nvtoken 上传**：页面里默认勾选“上传到 nvtoken 平台”。成功结果里如果包含 `access_token`、`refresh_token` 和 `email`，系统会额外上传到 nvtoken 的导入接口。

如果不想上传 nvtoken，可以在运行页面取消勾选“上传到 nvtoken 平台”。

## 本地配置

SMS API Key、SUB2、nvtoken 等敏感配置保存在本机 `data/local_config.json`，不会提交到 Git。公共状态接口逐项脱敏 SMS Key，只有密钥接口和显式导出返回完整值。运行页面可导入/导出这份 JSON，方便迁移到其他 Mac。

- OpenAI 主代理默认: `http://127.0.0.1:7897`
- SMS 最低价格默认: `0.01`
- SMS 最高价格默认: `0.1`
- Node 超时默认: `45` 秒
- 任务并发 / Node 并发默认: `5 / 5`
- 每号最大尝试默认: `10`
- 手机阶段超时默认: `480` 秒
- 鉴权额外重试默认: `1`

主代理仍可在页面里修改。SMS、SUB2 是否走代理由页面上的勾选项控制；邮箱取码按导入行自身的取码方式执行。

## 前端开发与构建

仓库已经包含可直接运行的 `frontend/dist/`，正常双击 `start.command` 不需要安装前端依赖。

修改 `frontend/src/` 后，需要重新生成生产资源：

```sh
cd frontend
npm install
npm run build
```

构建结果写入 `frontend/dist/`，Flask 会从 `/assets/` 提供带哈希的 JS/CSS 文件。构建完成后刷新 `http://127.0.0.1:18777/` 即可查看新版页面。

提交前建议运行完整检查：

```sh
mac_runtime/.venv/bin/python -m unittest discover -s tests -v
mac_runtime/.venv/bin/python -m py_compile \
  mac_overrides/web_gui.py \
  mac_overrides/sms_runtime.py \
  mac_overrides/task_progress.py \
  tests/test_sms_runtime.py \
  tests/test_task_progress.py
cd frontend
npx vue-tsc --noEmit
npm run build
```

## 常见问题

### 端口被占用

启动脚本固定使用 `18777` 端口，并会在启动前关闭旧的 gptPhone WebUI 实例。若仍提示端口被占用，通常是其他程序占用了 `18777`，先关闭那个程序后再双击 `start.command`。

### 依赖安装失败

确认本机能访问 Python/pip 依赖源，并且安装了 Homebrew。也可以先手动安装：

```sh
brew install python@3.13 node
```

然后重新双击 `start.command`。

### 页面空白或 assets 返回 404

如果浏览器控制台出现 `/assets/index-*.js` 或 `/assets/index-*.css` 404，先在项目里执行：

```sh
cd frontend
npm install
npm run build
```

然后重新双击 `start.command`，或强制刷新浏览器页面。不要直接双击 `frontend/dist/index.html`，页面需要通过 `http://127.0.0.1:18777/` 访问后端 API。

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

- `start.command`: mac 双击启动脚本，固定使用 `18777` 端口；再次启动会先关闭旧实例
- `plus_launcher.pyc`: 恢复出的入口字节码
- `business_pyc/`: 选出的业务 `.pyc` 模块
- `mac_overrides/`: mac 适配和 UI/逻辑覆盖层
- `mac_overrides/sms_runtime.py`: 多 SMS Key、余额隔离、并发门控、线路冷却、汇率和成本统计
- `mac_overrides/task_progress.py`: 线程安全的任务阶段追踪、阶段映射和六组实时计数
- `frontend/`: Vue 3 + Element Plus 管理台源码和生产构建
- `tests/`: 不产生真实短信费用的假 Provider 单元测试
- `data/`: 运行数据、配置、邮箱池状态
- `engine/`: 运行时准备出的引擎目录
- `external_assets/node_chain.dat`: 原包里的外部数据
- `disassembly/`: 反汇编结果，排查逻辑时参考
- `pycdc_attempt/`: best-effort 反编译结果，只能当提示看
- `tools/recover.py`: 恢复脚本

## 已知限制

当前工具依赖本机 Node.js 来运行 SentinelRunner 相关流程。mac 启动脚本会优先使用本机 `node`，并尝试准备 Node SentinelRunner 目录；如果相关资源不完整，真实授权链路可能会卡在 SentinelRunner 阶段。

另外，项目里的 `.pyc` 是 Python 3.13 字节码。当前常见反编译器对 Python 3.13 支持不完整，所以 `pycdc_attempt/` 不是可直接运行源码，最可靠的逻辑参考是 `disassembly/`。需要修改恢复业务逻辑时，应在 `mac_overrides/` 通过小范围运行时覆盖完成，并用测试验证原方法签名。
