# AGENTS.md

## 项目范围

GPT 注册中心（gptPhone）是 macOS 本地 Flask + Vue 3/Element Plus 应用，包含普通短信/OAuth 流程和 Free 注册流程。恢复的后端模块是 Python 3.13 运行时产物；可维护的后端改动放在 `mac_overrides/`，不要把 `business_pyc/`、`plus_launcher.pyc` 或 `pycdc_attempt/` 当作源码重构。

## 最高优先级：照抄 AutoRegister

Free 全协议链路和 RoxyBrowser 链路必须以同级项目 `/Users/lwh/projects/AutoRegister` 为行为基准，整体照抄其真实实现和调用顺序：会话建立、网络预检、匿名预热、OAuth/登录页面状态机、Sentinel、代理池分配、邮箱提交后的分支、OTP 页面、资料页、consent、OAuth 回调、Session 刷新、2FA、结果持久化、失败清理、Profile 生命周期、`connection_info` 对账和结构化诊断都按 AutoRegister 的逻辑实现。代理来自池并按任务上下文传递，但不得强制“一号一 IP”或因出口 IP 轮换拒绝健康任务。

Free 代理池是全协议和 RoxyBrowser 共用的单一 `healthy_random` 池：不按国家或代理组筛选、分配或展示，允许并发任务共享同一代理和出口 IP。代理预检只验证实际代理请求、HTTP 成功状态和出口 IP 格式；任务期间出口 IP 变化必须更新当前记录并继续健康任务，不得产生新的 `free_proxy_drift` 停止节点。历史国家/分组字段只能迁移为空，不能恢复为分配策略；RoxyBrowser 仅保留自身的 SOCKS4 协议能力限制。

Free 账号换绑统一使用纯协议链路：无论账号最初由全协议还是
RoxyBrowser 注册，换绑都必须复用 AutoRegister 对齐的协议会话、
Sentinel、password+TOTP 登录、`change_email` eligibility/begin/verify、
新邮箱 OTP、换绑后新邮箱重登、Session 刷新以及套餐/Plus 资格查询。
RoxyBrowser Profile 只作为原注册来源记录，换绑过程中不得打开、连接、
复用或创建 RoxyBrowser Profile，不得为换绑另行设计浏览器状态机。
换绑只允许使用已有密码和已启用 TOTP 的完整 Free 账号；邮箱验证码
继续使用 `mac_overrides/mailbox_otp_service.py` 的现有基线、旧码排除、
轮询、重发和阶段隔离策略。Free 注册本身仍按其配置的 protocol 或
RoxyBrowser 驱动执行，但注册驱动不得改变后续换绑协议。

唯一允许保留 AutoPhone 自己实现的是邮箱解析和邮箱验证码获取：继续使用 `mac_overrides/mailbox_otp_service.py` 及其现有策略模式，包括来源解析、请求前基线、旧验证码排除、消息身份判断、时间过滤、轮询、重发和阶段隔离。除这些邮箱取件边界外，不得自行设计另一套注册链路，不得为了兼容旧实现而保留与 AutoRegister 不同的主流程。

对照位置：

- 协议注册：`/Users/lwh/projects/AutoRegister/core/chatgpt_auth.py`、`core/openai_auth.py`、`core/sentinel_runner.py`、`main.py`。
- RoxyBrowser：`core/roxy_registration.py`、`core/roxybrowser_client.py`、`core/otp_utils.py`、`core/humanize.py`、`core/live_check_service.py`、`config/proxy.py`、`config/roxybrowser.py`。
- 只吸收实现逻辑，不复制任何账号、邮箱密码、Cookie、Token、验证码、代理凭据、运行数据或第三方授权信息。
- 开源参考副本仅作只读对照；新建的临时副本使用完必须删除。项目保留的长期只读副本除非用户明确要求，不得删除。

### Free 三链路参考与共享边界

- Camoufox 参考项目为 `/Users/lwh/projects/aBaiFreeGPT`，当前对照提交为 `0b4b7197863d49b54875a7d0c7ef5bc0ee35aafa`，许可证为 AGPL-3.0；该副本只读，不承载 AutoPhone 运行数据。
- protocol 和 RoxyBrowser 只能参考同级 `/Users/lwh/projects/AutoRegister`；Camoufox 只能参考同级 `/Users/lwh/projects/aBaiFreeGPT`。除这两个本地对照项目外，不再引入其他项目作为行为基准。
- 对照项目只吸收代码和调用顺序；禁止复制其运行数据、账号、邮箱 provider、凭据、Cookie、Token、验证码、代理信息或第三方授权状态。
- Free 注册驱动包括 `protocol`、`roxybrowser`、`camoufox`。三条链路共用 `${GPTPHONE_DATA_DIR}/free_register/` 下的同一个邮箱池。
- 三条链路必须统一调用 `mac_overrides/mailbox_otp_service.py` 的邮箱 URL 解码和策略模式，包括来源解析、请求前基线、旧验证码排除、消息身份判断、时间过滤、轮询、重发和阶段隔离；浏览器驱动不得引入固定邮箱格式或另一套邮箱 provider。
- 新注册默认优先走 passwordless 邮箱 OTP；只有实际进入并提交注册密码页时才使用固定密码 `Aa150010@150010` 并保存密码。已有账号登录、2FA 重试和换绑必须使用已保存的真实密码。
- Session、2FA、套餐/Plus 和结构化错误使用统一业务结果契约，但协议 HTTP、Roxy Selenium/CDP、Camoufox async page 只在 transport adapter 层保持差异。
- RoxyBrowser/Camoufox 只记录注册来源；换绑始终复用纯协议链路，不打开、连接、复用或创建浏览器 Profile。

## 编辑边界和数据隔离

## 日志中心与故障审计

- 所有普通流程、Free protocol/RoxyBrowser/Camoufox、Free 换绑、支付和网络诊断错误都必须产生可引用的 `incident_id`（日志中心显示为 `LOG-日期-短标识`）；排查优先使用日志 ID、稳定任务/批次/账号标识和时间范围，不要求人工翻阅自由文本日志。
- 新链路必须写入统一的结构化诊断事件，至少包含 `event_id`、`incident_id`、时间、链路、驱动、任务/批次、`node_code`、中文 `node_label`、结果、失败代码、可重试属性和脱敏处理建议；不得建立无法检索的私有日志格式。
- 诊断事件只追加，不原地覆盖；重试、浏览器关闭、代理释放、清理和进程恢复不得覆盖首个真实业务失败。清理或系统错误必须作为关联事件保存。
- 日志中心的诊断索引只保存脱敏事件和 HMAC/短指纹，不能成为普通流程与 Free 流程共享邮箱、代理、账号结果或运行状态的通道。
- 日志写入前和导出前都必须执行字段白名单与敏感信息脱敏；密码、Token、Cookie、验证码、手机号、TOTP Secret、OAuth 查询参数和代理凭据不得落盘。脱敏失败时禁止写入原文。
- 删除日志中心指定故障或清空全部诊断日志，只能删除 `${GPTPHONE_DATA_DIR}/diagnostics/` 下的诊断索引、事件和别名，不能删除邮箱池、代理池、账号结果、任务结果或 Free 数据。
- 每个日志 ID必须可复制给 GPT；GPT 导出必须区分已确认事实、证据时间线、推导归因和未确认信息，不得把推测写成事实。
- 诊断索引必须报告自身的写入失败、丢弃、哈希完整性异常和存储健康状态；事件哈希断链时必须在日志详情中明确显示。
- 新增节点时同步登记稳定代码、中文名称、可重试规则、处理建议和测试；修改诊断契约时同步更新迁移、后端测试、前端类型和 `frontend/dist/`。
- 日志中心不自动执行真实注册、真实代理测试、浏览器操作或安全挑战绕过。

- 后端行为改动放在 `mac_overrides/`，`mac_overrides/web_gui.py` 负责加载恢复模块和应用定向覆盖。
- 普通短信/OAuth 与 Free 注册的数据必须隔离。Free 配置、邮箱/代理池、任务、日志、锁和结果放在 `${GPTPHONE_DATA_DIR}/free_register/`，普通流程不得读取、聚合、修改或消耗这些状态。
- 支付链接工具只使用 `${GPTPHONE_DATA_DIR}/payment_tools/`，网络诊断只使用 `${GPTPHONE_DATA_DIR}/network_tools/`，不得复用注册任务状态。
- 前端源代码放在 `frontend/src/`；`frontend/dist/` 已纳入版本控制，前端源代码有变化时必须重新构建并更新产物。
- 不要提交 `data/`、`mac_runtime/`、`engine/`、`node_chain.dat`、`frontend/node_modules/`、缓存、导出文件或秘密。

## 安全和诊断

- 未经用户明确同意，不得使用 `computer-use`、应用内浏览器、Chrome、Playwright 或真实浏览器操作。
- 不得在日志、公共 API、任务结果或持久化记录中暴露邮箱密码、代理凭据、Cookie、OAuth URL 查询参数、授权头、access/refresh/ID/admin token、短信/邮箱验证码、手机号或 TOTP 秘密；公共状态只能使用掩码或短指纹。
- 每个失败必须保留稳定节点代码、中文节点名称、HTTP 状态/服务商代码（如有）和脱敏的可操作原因；不能用“操作失败”或“failed”覆盖首个真实节点。
- Cloudflare、人机验证和安全挑战只记录并停止，禁止自动绕过。Session 失效、网络临时错误和业务限流必须按 AutoRegister 的重试边界处理；不得把业务 429 当成可重复提交信号。
- 代理测试必须使用所选代理声明的协议，清除继承的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`，不得静默切换节点或回退到 Clash。当前主机 Clash Verge HTTP 代理是 `http://127.0.0.1:7897`；`12334` 不是有效配置，出现时必须追溯来源并修复。
- 测试和诊断不得覆盖用户运行数据；需要临时数据目录时使用临时目录，任务结束后删除由本次任务创建的临时副本。

## 兼容和实现要求

- 覆盖恢复模块前先保存原方法，保持原有可调用签名（包括 keyword-only 参数），只做窄范围覆盖。
- 对不确定的恢复方法先查 `disassembly/index.json` 的对应切片，并在 Python 3.13 环境用 `inspect.signature` 确认签名。
- 保留已有配置字段和页面顺序，除非用户明确要求删除或调整。
- OTP 的请求基线、旧码排除和阶段状态必须按注册、已有账号登录、2FA enrollment 分开；取消、重试、清理不得覆盖原始终止原因。
- 真实邮箱注册或真实代理动作不是普通静态验证的一部分；只有用户明确授权时才可执行，且不得把失败的真实尝试伪装成成功。

## 发布和验证

- 用户可见的版本说明统一写在 `frontend/src/releaseNotes.ts`；涉及用户可见改动时同步更新版本号和说明，并重建 `frontend/dist/`。
- Free 运行时版本必须与 `frontend/src/releaseNotes.ts` 的 `freeRuntimeVersion` 同步，并在 `mac_overrides/free_runtime_info.py` 与对应版本测试中一起更新；用户可见改动还必须重建并提交 `frontend/dist/`。
- 后端验证：

  ```sh
  mac_runtime/.venv/bin/python -m unittest discover -s tests -v
  mac_runtime/.venv/bin/python -m py_compile mac_overrides/error_observability.py mac_overrides/web_gui.py mac_overrides/sms_runtime.py mac_overrides/task_progress.py
  ```

- 前端验证：

  ```sh
  cd frontend
  npx vue-tsc --noEmit
  npm run build
  ```

- 最后运行 `git diff --check`。除非用户明确要求，不要启动或重启 Flask 服务，也不要点击真实注册、短信、SUB2、Pixel、支付提取或代理测试动作。
