# 自动接码机（gptPhone）macOS 使用说明

这是一个 macOS 可双击运行的 Element Plus WebUI 工具。主要用途是批量导入邮箱账号，自动走 ChatGPT/OpenAI Auth 授权、邮箱取码、必要时手机接码，并把成功结果上传到 SUB2；每批结束后还可选择批量上传到 Pixel 和 NV。

## 快速启动

Mac 需要已安装 Git。建议同时安装 [Homebrew](https://brew.sh/)，启动脚本可通过 Homebrew 补齐 Python 3.13 和 Node.js。

第一次拉取代码：

```sh
git clone https://github.com/aaa150010/AutoPhone.git AutoPhone
cd AutoPhone
chmod +x start.command
./start.command
```

已经拉取过代码时，在现有目录更新并启动：

```sh
cd /你的路径/AutoPhone
git pull --ff-only
chmod +x start.command
./start.command
```

也可以在 Finder 中双击 `start.command`。首次运行需要创建 Python 虚拟环境、安装依赖并构建前端，时间会比后续启动长。更新代码不会覆盖 `data/` 中的邮箱池、运行配置、结果和上传记录；不要为了更新而删除 `data/`。

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
http://127.0.0.1:18777/accounts
http://127.0.0.1:18777/settings
```

端口固定为 `18777`。如果重复双击启动，脚本会先关闭旧的 WebUI 实例，再在同一端口启动新的。

左侧栏固定显示“自动接码机”品牌，以及“运行中心”“邮箱管理”“URL测试”“账号管理”“运行配置”五个入口。侧栏底部会持续显示全局运行状态和最近一次通知状态，不需要同时打开多个浏览器标签页。

停止运行：关闭启动脚本打开的 Terminal 窗口，或在 Terminal 里按 `Ctrl-C`。

## mac 双击权限说明

如果双击 `.command` 没反应，或提示没有权限，执行：

```sh
chmod +x start.command
```

如果 macOS Gatekeeper 提示来自未知开发者，可以在 Finder 里右键 `start.command`，选择“打开”，再确认运行。

## 页面使用流程

### 1. 导入邮箱

打开左侧“邮箱管理”，点击右上角“导入邮箱”，在弹出的批量导入 Dialog 中每行粘贴一个账号，再点击“追加导入”。导入会追加到现有邮箱池，完全重复的行会自动跳过。

邮箱表格支持：

- 搜索邮箱、状态和说明
- 按状态筛选和分页
- 邮箱账号正常显示；密码列始终显示 `*****`，点击后才向后端请求本行明文并直接写入系统剪贴板
- 单行“查码”，验证码显示在对应行
- 勾选后恢复为可用状态或删除
- 查看 SUB2 状态，并对勾选的邮箱批量测试连接
- 按“SUB2 异常（全部）”或“SUB2 401（需重跑）”筛选；未测试和未关联不算异常
- 查看成功任务的接码成本；悬浮金额可查看美元报价、USD/CNY 汇率和汇率日期
- 实时查看每个运行中邮箱所在的业务节点和已停留秒数

表格“状态”列表示邮箱池当前状态：`可用`、`运行中`、`已使用`或`失败`。邮箱关联任务运行时会实时切换为“运行中”；旁边的“运行状态”列显示“OAuth 创建节点”“正在获取手机号”“等待短信验证码”等具体节点。任务结束后，“状态”回到最终池状态，“运行状态”保留并冻结在最后一个有效节点。

成功后邮箱会保留在邮箱池并标记为“已使用”，不会因为上传完成而消失。只有手动“恢复可用”后，才允许再次被任务领取。SUB2 状态列会显示 `200 健康`、`401 Token失效`、`429 额度受限`、`404 账号不存在`、`超时`、`网络错误`、`未测试`或`未关联`；只有账号级 `401` 适合恢复后重跑，`429` 只展示状态。

复制密码时，明文不会插入页面、提示消息或前端响应式状态；浏览器不支持安全 Clipboard API 时会拒绝复制。若邮箱池在点击前已经变化，后端会拒绝过期行并刷新列表，避免复制到另一条记录的密码。

### 2. 填写运行配置

打开左侧独立的“运行配置”页面，按需填写：

- 代理地址及 SMS、邮箱取码、SUB2/NV 的代理开关
- 目标数量、并发数、Node 并发数和 Node 超时
- SMSBower 最低/最高价格、短信超时、手机阶段超时、每平台最大尝试和一个或多个 API Key
- 鉴权额外重试次数；`0` 表示失败后不额外重试，默认 `1`
- SUB2 地址、账号、管理密码和分组
- Pixel 上传 worker 数，以及 NV 导入地址和 API Key
- QQ 邮箱通知账号、SMTP 授权码、收件人、停滞阈值和通知事件

“每平台最大尝试”默认和上限都是 `15`；每个任务的总尝试数按已启用且配置了 Key 的平台数计算，最多 `45`。手机阶段超时默认和上限都是 `1800` 秒。

SUB2 管理密码、NV API Key 和 SMS API Key 都使用 Element Plus 原生密码输入框，点击输入框右侧眼睛可以显示或隐藏当前内容。SMS Key 编辑器右侧的加号可新增一行，每行独立显示和删除，至少保留一个可填写行。保存时会去除空行、首尾空格和重复 Key，并保留原顺序。Pixel 登录密码由 Aliyun 管理代理保管，本机不保存或回显。

配置有改动后，页面会显示“有未保存修改”。切换入口、浏览器前进后退或关闭/刷新页面时都会提醒；运行中心也会禁止用未保存草稿启动，并引导回运行配置页。保存成功后草稿成为当前活动配置；从配置页启动成功后会自动进入运行中心。

### 3. 配置邮件通知

邮件通知位于运行配置的最后一个分区，仅支持 QQ 邮箱，程序固定使用官方 `smtp.qq.com:465` 和 SSL，不提供其他服务商或自定义服务器选项。

启用通知时必须填写 QQ 发件账号、SMTP 授权码和至少一个收件邮箱；收件人可添加多个，重复地址会自动去除。发件人地址留空时使用发件账号。SMTP 授权码需要在 QQ 邮箱后台生成，不是邮箱登录密码。

可选择以下通知事件：

- **批次完成**：默认开启。无论全部成功、部分失败还是全部失败，每轮只发送一封最终汇总，包含处理总数、成功、失败、停止、耗时和可用时的运行成本。
- **异常结束**：默认开启。运行 watcher 退出后仍存在未进入终态的任务时发送。
- **运行停滞**：默认开启。运行中连续一段时间没有任务进展时发送，默认阈值为 `10` 分钟。
- **SMS Key 耗尽**：默认开启。全部 SMS Key 耗尽并触发安全停止时立即发送。
- **手动停止**：默认关闭，需要时可单独开启。

同一轮运行的同类事件最多发送一次；停滞或 SMS Key 耗尽的即时提醒不会替代之后的最终汇总。邮件正文只包含批次汇总，不包含邮箱账号、任务 ID、密码、Token、手机号、代理或底层原始错误。

“发送测试通知”会直接使用当前表单草稿测试 SMTP，不会先保存配置，也不会启动任务。测试和正式通知发送失败都不会改变任务状态。

### 4. 保存、预检和运行

运行配置下方的操作栏按两行三列均匀排列，顺序为：

1. **导入配置**：读取本机 JSON，兼容新版 Key 数组和旧版单 Key；导入成功后立即应用并清除未保存状态。
2. **导出配置**：二次确认后下载包含可迁移敏感信息、但不含 NV API Key 的 JSON。
3. **保存配置**：保存当前页面设置。
4. **真实链路预检**：检查所有 SMS Key 余额、SMS 报价、SUB2、Node 链路等条件，不启动批量任务。
5. **开始运行**：打开本次上传目标弹窗，再使用当前邮箱池启动任务。Pixel、NV 每次打开都默认不勾选，选择不会写回运行配置。
6. **停止**：向正在运行的任务发送安全停止请求。

建议第一次配置或修改 SUB2/代理后，先保存配置，再执行一次真实链路预检，预检通过后开始运行。取消运行弹窗不会启动任务；确认后，即使 Pixel 或 NV 上传失败，注册任务和已经保存的成功结果也不会变成失败。Pixel 账号测试、共享和上传重试在“账号管理”页单独执行，不会启动注册流程。

“运行中心”工具栏也提供“导入邮箱”，可直接打开与“邮箱管理”相同的批量追加弹窗；导入成功后首页的可用邮箱数量和开始按钮会立即更新。

### 5. 查看运行状态和结果

“运行中心”顶部显示可用邮箱、运行中、成功、未成功和运行成本五项统计。诊断区按排队等待、OAuth 节点、邮箱验证、获取手机号、短信接码、收尾上传六组汇总当前未结束任务，同时展示并发占用、SMS Key 健康/余额和异常汇总。

下方“任务结果”和“运行日志”并排独立滚动，均支持搜索、筛选和聚焦展开；日志可控制自动滚动。任务结果可分别导出成功、未成功或全部记录。任务表的“运行状态”按秒更新，失败或停止后保留最后业务节点并冻结计时。

`/api/state` 的任务项会返回 `progress.code`、`progress.label`、`progress.group`、`progress.entered_at` 和 `progress.finished_at`，`runtime.stage_counts` 固定返回上述六组计数。这些字段只包含节点名称和时间，不包含邮箱密码、手机号、SMS Key、Token 或底层链路事件详情。

### 6. 管理 Pixel / NV 上传记录

打开“账号管理”可在 Pixel 和 NV 两个平台间切换。Pixel 视图显示 Aliyun Pixel 管理代理返回的目标、账号、批次和投递记录；NV 视图显示批次完成度、分片账号数、尝试次数、脱敏错误和人工重试操作。账号管理页不会显示登录密码、API Key 或 OAuth 凭据。

`pixel-2` 至 `pixel-7` 是自动上传目标。`pixel-1`（账号管理中对应 `1745627971@qq.com`）仍可查看、测试连接和手动重新授权，但明确标记为“不自动上传”，不会被注册成功后的自动流程或“一键共享”提交。

批量公开共享会为每个账号独立随机选择 `3` 至 `10` 的并发，并设置为公开；一键共享会扫描六个自动上传目标的全部分页账号后执行同样的操作。接口表面成功后仍会回查实际共享状态和并发，未达到公开或 `3–10` 范围的账号会保留为失败，便于再次处理。

Pixel 上传记录按批次来源和目标保存导入任务、生成的随机账号名、远端账号 ID、实际并发、尝试次数和脱敏错误。NV 上传记录保存批次、阶段、次数、安全 HTTP/provider 状态和脱敏错误。导入失败、共享失败、部分失败、需人工确认和源数据不可用都会持久化，不会把注册成功改成失败。记录分别保存在 `data/pixel_upload_records.json` 和 `data/nv_upload_records.json`，只引用成功结果文件，不复制 token。

### 7. 导入和导出配置

“导入配置”和“导出配置”用于迁移本机保存的 SMS、SUB2、NV 地址和邮件通知配置。新版 JSON 使用 `sms_api_keys: string[]`；旧文件里的 `sms_api_key` 会自动变成一行，不会按 `-` 拆分。Pixel/NV 的本次上传选择不会进入导出配置，NV API Key 也不会写入下载文件，需要在目标 Mac 的运行配置页单独填写。

SMTP 授权码在公共状态和普通配置响应中保持 `********` 遮罩，并通过固定密钥标识单独读取。完整下载导出会在二次确认后写入 SMS Key、SMTP 授权码及其他可迁移密钥，但始终排除 NV API Key。导出文件应仅保存在可信设备上，不要提交到 Git 或发送给他人。

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

### 4. 已有 GPT 账号 + TOTP

```text
GPT账号|登录密码|2FA密钥
```

这是 mac override 新增的格式。系统会用账号密码登录，并根据 2FA 密钥本地生成 TOTP 临时验证码。三段 TOTP 支持连续横线、`|`、Tab、逗号、分号、冒号及对应全角符号，例如：

```text
GPT账号----登录密码----BASE32密钥
GPT账号|登录密码|BASE32密钥
GPT账号<Tab>登录密码<Tab>BASE32密钥
```

导入时会先判断 OAuth 四段格式，再判断三段 TOTP，因而同一个邮箱池可以混放 Outlook OAuth 与 TOTP 账号。TOTP 行必须包含合法邮箱、非空密码和可校验的 Base32 密钥；注释行、字段缺失、无效 Base32 或无法明确识别的行会被拒绝。密码中的普通标点不会被误当成分隔符。页面、日志和接口只返回脱敏邮箱行，不回显密码、2FA 密钥或 OAuth 凭据。

2FA 密钥本身不会过期；它每 30 秒生成一个新的 6 位 TOTP。程序会先完成 Sentinel/header 准备，再在发送前生成动态码；当前窗口不足 5 秒时会等待下一个窗口。服务端返回 `Invalid authorization step` 时会废弃当前 challenge 并建立新的 OAuth 会话，而不是把它误判成密码或永久 2FA 错误。

## 关于手机验证码

手机验证码不是每条邮箱链路都强制需要。

运行时会先完成邮箱/账号登录。如果 OpenAI/ChatGPT 页面没有要求手机验证，流程会直接继续 OAuth callback、token exchange 和 SUB2 上传。只有页面进入 `add_phone`、`contact_verification`、`phone_number_collection` 等手机验证状态时，才会调用 SMS 接码平台买号、发短信、等待手机验证码。

### 多 SMS Key 与余额

预检会并行查询各 SMSBower Key 的美元余额，再通过健康 Key 查询并短缓存最低可用报价；报价失败时最多再切换一个 Key，避免 Key 越多请求量越大。余额并行度会随 Key 数量增加，最多同时检查 `8` 个 Key，不写死为双 Key。每行 Key 会显示“可用 $1.25”“余额不足 $0.00”“Key 无效”或网络/限流状态。

- 部分 Key 余额不足或不可用时，页面会列出 Key 序号，其余 Key 仍可运行。
- 所有 Key 都余额不足时，预检失败并阻止启动。
- 运行中单个 Key 耗尽时，只停用该 Key，后续订单切换到其他 Key。
- 所有 Key 都耗尽时，不再创建新短信订单；已经领取的号码仍会处理完成，后续需要号码的任务会得到 `sms_balance_insufficient`。
- 号码从哪个 Key 领取，后续查码、完成和取消就固定使用同一个 Key。日志和状态只记录 SHA-256 短指纹，不记录原始 Key。

多 Key 池会使用全部健康 Key，并按“最少占用 + 轮询”分配。两把 Key 时自然均衡到两边，增加 Key 后会自动摊开，不需要修改调度逻辑。相同 Key 的相同余额告警每次运行只显示一次，避免状态轮询重复弹窗。

### 并发与重试策略

- 批量任务并发和 Node 并发默认都是 `5`。
- `target_count` 会限制本次实际任务总数；调度器只预留本批目标邮箱，执行线程不超过 `min(target_count, concurrency)`，同一批次不会反复领取刚归还的邮箱。
- 手机号提交每批从基础并发 `2` 开始，上限 `5`，相邻提交至少间隔 `750ms`。每 4 次真实 2xx 提升 1 个槽位；429、5xx 或临时网络错误立即降低 1 个槽位并沿用 `2/4/8` 秒退避。
- 未验证线路同时使用 `1` 个号码；已有 OTP 发出或成功记录的线路最多并发 `2`。
- 线路排序优先使用本机历史有效号码成功率；静态优先线路只负责没有历史样本时的冷启动，不额外发送线路预热请求。
- OpenAI 临时服务错误复用同一个号码，并在所有任务之间共享 `2/4/8` 秒退避，避免并发任务同时重试形成尖峰。
- 已使用号码线路冷却 `10` 分钟，可疑相似号码线路冷却 `30` 分钟，连续两次没有验证码的线路冷却 `5` 分钟。
- 每个平台最多尝试 `15` 个号码；每个任务按启用平台数合计，最多尝试 `45` 个号码。手机阶段最多运行 `1800` 秒。
- 手机已验证后如果 SUB2 授权会话恰好过期，会按“鉴权额外重试次数”建立全新会话继续；设置为 `0` 时不会额外重试。

这些限制只约束手机号阶段，不会把整个任务并发强制降到 `2`。

按当前运行日志，双 Key 的建议起点是任务并发 `6`、Node 并发 `5`。增加 SMS Key 会提升余额隔离和 SMS API 请求的可用吞吐，但 OpenAI 手机提交门仍是独立瓶颈，因此任务并发不应按 Key 数量线性放大；应从 `6/5` 起跑，再按成功吞吐和临时服务错误率调整。

### 接码成本

收到短信验证码后，该激活订单的美元报价会计入任务；没有收到验证码的订单保留脱敏结果明细，但不计入成功接码成本。任务结果保存：

- `sms_cost_usd`：有效激活订单的美元合计
- `sms_cost_cny`：换算后的人民币金额
- `sms_exchange_rate`、`sms_exchange_date`：换算汇率和日期
- `sms_order_outcomes`：不含原始激活 ID 和 Key 的订单明细

USD/CNY 每 24 小时从 ECB 日汇率推导一次。网络失败时先使用上次缓存，没有缓存时回退到 `7.20`。历史结果没有成本字段时，邮箱表格显示“暂无”。

## 结果上传

单个任务成功后会先把授权结果上传到配置好的 SUB2 地址和目标分组。Pixel 和 NV 不在单账号完成时上传；只有整批注册任务全部进入终态后，程序才收集该批已经成功落盘的账号，并按开始运行弹窗中的选择入队。失败、停止或中断账号不会进入上传，部分成功批次仍会上传成功账号。

Pixel 按邮箱域名分组，每组最多 100 个账号合并为一个导入任务，并投递到 `pixel-2` 至 `pixel-7`；`pixel-1` 不参与自动批量上传。每个目标为账号生成独立的 `acct-<12位随机十六进制>@<原域名>` 名称。导入成功后，每个新账号独立随机设置 `3–10` 并发并开启公开共享；共享失败时只重试失败账号，不重新导入。

NV 同样按最多 100 个账号分片，提交 `access_token`、`refresh_token`、`email` 和固定 `type: codex`。网络错误、429 和 5xx 自动尝试 3 次；其他 4xx 保留脱敏诊断等待人工重试。Pixel/NV 队列相互独立，任何上传失败都不会修改注册成功状态。批次选择和成功结果清单持久化后，进程重启也能恢复未完成的入队操作。

## 本地配置

SMS API Key、SUB2、NV 地址/API Key、SMTP 授权码和通知收件人等配置保存在本机 `data/local_config.json`，不会提交到 Git。公共状态接口不会返回原始凭据；SMS Key、代理密码、SUB2 管理密码、NV API Key 和 SMTP 授权码按密钥处理。NV API Key 只通过专用密钥接口供本机配置页读取，不进入下载导出；Pixel 登录密码只保存在远端 Aliyun 管理代理，不写入本机配置。运行配置页可导入/导出其余配置，方便迁移到其他 Mac。

Pixel、NV outbox 和批次清单分别保存在 `data/pixel_upload_records.json`、`data/nv_upload_records.json`、`data/batch_upload_manifests.json`。它们以原子方式记录结果文件相对路径、批次、阶段、次数和脱敏诊断，不保存 OAuth Token、API Key、管理员 token 或原始响应。`data/` 目录及其上传记录不应提交 Git。

- OpenAI 主代理默认: `http://127.0.0.1:7897`
- SMS 最低价格默认: `0.01`
- SMS 最高价格默认: `0.15`
- Node 超时默认: `45` 秒
- 任务并发 / Node 并发默认: `5 / 5`
- 每平台最大尝试默认: `15`（每任务总上限 `45`）
- 手机阶段超时默认: `1800` 秒
- 鉴权额外重试默认: `1`
- 手机提交基础并发 / 自适应上限默认: `2 / 5`

主代理仍可在页面里修改。SMS、邮箱取码、SUB2/NV 是否走代理由页面上的勾选项控制；NV 默认直连，只有勾选 SUB2/NV 上传代理时才使用主代理。

## 前端开发与构建

仓库已经包含可直接运行的 `frontend/dist/`。每次启动 `start.command` 时，脚本会自动检查 Vue 依赖并重新执行生产构建，然后再启动 Flask；因此修改 `frontend/src/` 后重启服务即可加载新页面。

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
  mac_overrides/batch_upload_runtime.py \
  mac_overrides/chatgpt_totp.py \
  mac_overrides/importer_scheduler.py \
  mac_overrides/legacy_ui.py \
  mac_overrides/mailbox_admin.py \
  mac_overrides/run_notifications.py \
  mac_overrides/runtime_policy.py \
  mac_overrides/pixel_runtime.py \
  mac_overrides/nv_runtime.py \
  mac_overrides/sms_runtime.py \
  mac_overrides/sms_web.py \
  mac_overrides/sub2_runtime.py \
  mac_overrides/task_progress.py \
  mac_overrides/web_routes.py \
  tests/test_chatgpt_totp.py \
  tests/test_batch_upload_runtime.py \
  tests/test_importer_scheduler.py \
  tests/test_legacy_ui.py \
  tests/test_mailbox_admin.py \
  tests/test_run_notifications.py \
  tests/test_runtime_policy.py \
  tests/test_sms_runtime.py \
  tests/test_sms_web.py \
  tests/test_pixel_runtime.py \
  tests/test_nv_runtime.py \
  tests/test_sub2_runtime.py \
  tests/test_task_progress.py \
  tests/test_web_gui_security.py \
  tests/test_web_routes.py
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
- `mac_overrides/web_gui.py`: recovered 模块加载、窄 monkeypatch 注册和各独立覆盖模块装配
- `mac_overrides/chatgpt_totp.py`: TOTP 邮箱格式、验证码生成和认证传输补丁
- `mac_overrides/legacy_ui.py`: recovered 旧版页面的兼容 HTML/JS 注入
- `mac_overrides/mailbox_admin.py`: 邮箱状态、查码、导入、删除和恢复服务
- `mac_overrides/run_notifications.py`: 邮件通知配置、SMTP 发送、事件去重和运行停滞判断
- `mac_overrides/web_routes.py`: Flask 路由装配和配置/预检/启停生命周期协调
- `mac_overrides/pixel_runtime.py`: Pixel 目标代理、单线程上传队列、公开共享和按目标重传
- `mac_overrides/sub2_runtime.py`: SUB2 管理鉴权、SSE 连接测试、状态快照和批量测试
- `mac_overrides/sms_runtime.py`: 多 SMS Key、余额隔离、并发门控、线路冷却、汇率和成本统计
- `mac_overrides/sms_web.py`: SMS Provider、智能线路和 Web 运行时接线
- `mac_overrides/importer_scheduler.py`: 目标数量控制、批次池条目预留和有界执行线程
- `mac_overrides/runtime_policy.py`: 授权运行时的窄范围恢复策略
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

邮件通知由 WebUI Python 进程内的后台 worker 发送，因此无法覆盖 Mac 关机、整机断网或 Python 进程直接退出等场景。这些场景需要独立的外部监控；进程仍在但 SMTP 暂时不可用时，本次发送会标记失败且不会自动重试，也不会影响批次任务状态。

另外，项目里的 `.pyc` 是 Python 3.13 字节码。当前常见反编译器对 Python 3.13 支持不完整，所以 `pycdc_attempt/` 不是可直接运行源码，最可靠的逻辑参考是 `disassembly/`。需要修改恢复业务逻辑时，应在 `mac_overrides/` 通过小范围运行时覆盖完成，并用测试验证原方法签名。
