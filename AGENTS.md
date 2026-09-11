# AGENTS.md

## 1. 项目范围与运行形态

GPT 注册中心（gptPhone）是 macOS 本地 Flask + Vue 3/Element Plus 应用，包含普通短信/OAuth 流程和 Free 注册流程。前端开发服务器通过 Vite 热更新访问（`frontend/vite.config.ts`：5173 代理 `/api` 到 18777），后端 Flask 服务监听 18777。

恢复的后端模块是 Python 3.13 运行时产物；可维护的后端改动放在 `mac_overrides/`，`mac_overrides/web_gui.py` 负责加载恢复模块和应用定向覆盖。不要把 `business_pyc/`、`plus_launcher.pyc` 或 `pycdc_attempt/` 当作源码重构。

## 2. 参考项目与链路分工

本机以下四个同级项目都是 AutoPhone 的参考项目，地位平级：优化实现、排查故障时按链路查对应项目即可，不存在"第一基准/兜底"的优先级链。无论参考谁，都不得用其推测覆盖 AutoPhone 已有行为；只吸收代码和调用顺序。

| 参考项目 | 适用链路/场景 | 重点位置 |
|---|---|---|
| `/Users/lwh/projects/New_V1.11.18_win` | protocol 注册链路 | `browser_flow/runner/src/browserService.js`、`browser_flow/runner/register_runner.js`、`browser_flow/runner/src/protocolCapture.js` 及包内测试 |
| `/Users/lwh/projects/AutoRegister` | protocol 注册链路；换绑/密码/2FA/重试边界 | `core/chatgpt_auth.py`、`core/openai_auth.py`、`core/sentinel_runner.py`、`main.py` |
| `/Users/lwh/projects/any-auto-register` | protocol 注册链路；邮箱/OTP 抽象思路；换绑/2FA/密码；代理池 | `platforms/chatgpt/protocol/`（`auth_flow.py`、`sentinel.py`/`sentinel_quickjs.py`、`two_factor.py`、`phone_flow.py`、`token_refresh.py`、`mail_provider.py`、`mailbox_adapter.py`）及 `core/proxy_pool.py` |
| `/Users/lwh/projects/aBaiFreeGPT` | camoufox 注册链路（只读行为对照） | 会话建立、网络预检、匿名预热、OAuth/登录页面状态机、Sentinel、代理池分配、邮箱提交后的分支、OTP 页面、资料页、consent、OAuth 回调、Session 刷新、2FA、结果持久化、失败清理、`connection_info` 对账和结构化诊断按其调用顺序执行 |

- 参考项目对照状态：aBaiFreeGPT 当前对照提交 `0b4b7197863d49b54875a7d0c7ef5bc0ee35aafa`（AGPL-3.0）；any-auto-register 当前对照提交 `dfc697cb2fd39d14e7489ff306aaed8ad798e3f9`（MIT，仅供学习研究）。
- 参考副本一律只读，不承载 AutoPhone 运行数据；除这四个本地项目外，不再引入其他项目作为行为基准。新建的临时副本使用完必须删除；项目保留的长期只读副本除非用户明确要求，不得删除。
- 邮箱/OTP 取件可参考 any-auto-register 的 mailbox 抽象思路，但 AutoPhone 的实现唯一基线是 `mac_overrides/mailbox_otp_service.py`（见 3.4）。
- Remail 外部服务文档（从 Remail 购买邮箱的订单同步与导入字段依据）：`https://remail.aishop6.com/docs`（Open API 1.0.0，`rk-` 开头 Key；订单字段为 `orderNo`/`deliveryEmail`/`serviceToken`/`status`，状态枚举 `pending_payment|paid|active|completed|refunded|failed|closed`，`serviceToken` 为可选字段，失败原因见 `failureCode` 如 `insufficient_inventory`；禁止把 Key、serviceToken 或订单凭证写入日志）。
- 只吸收实现逻辑，不复制任何账号、邮箱密码、Cookie、Token、验证码、代理凭据、运行数据或第三方授权信息。

### protocol 注册入口顺序

protocol 当前注册入口必须按同一 HTTP session 执行 `providers → csrf → signin/openai(screen_hint=login_or_signup) → auth authorize → email OTP → about_you → create_account → ChatGPT callback → /api/auth/session accessToken`；已返回可识别 OTP/资料页时不得重复提交邮箱，手机号页只停止并不得调用接码平台。

## 3. Free 注册业务规则

### 3.1 驱动与数据

- Free 注册驱动仅包括 `protocol`、`camoufox`，两条链路共用 `${GPTPHONE_DATA_DIR}/free_register/` 下的同一个邮箱池。历史数据中的 `driver=roxybrowser` 只读展示为历史链路，不得再创建、启动、重试或配置该驱动，也不得调用 Roxy API、Profile 或清理逻辑。
- 注册来源只允许记录 `protocol` 或 `camoufox`；历史 Roxy 来源保留为只读兼容信息，换绑始终复用纯协议链路。
- 普通短信/OAuth 与 Free 注册的数据必须隔离。Free 配置、邮箱/代理池、任务、日志、锁和结果放在 `${GPTPHONE_DATA_DIR}/free_register/`，普通流程不得读取、聚合、修改或消耗这些状态。

### 3.2 代理池

Free 代理池是两条链路共用的单一 `healthy_random` 池：不按国家或代理组筛选、分配或展示，允许并发任务共享同一代理和出口 IP。任何链路都不得绑定账号注册时的历史代理：注册、快速/深度测活、套餐查询、换绑等所有动作统一在执行时从当前健康池分配代理、用完释放，账号行上保存的代理仅作注册记录展示。代理预检只验证实际代理请求、HTTP 成功状态和出口 IP 格式；任务期间出口 IP 变化必须更新当前记录并继续健康任务，不得产生新的 `free_proxy_drift` 停止节点。历史国家/分组字段只能迁移为空，不能恢复为分配策略。

### 3.3 注册主流程与密码/2FA

- 新注册默认优先走 passwordless 邮箱 OTP；只有实际进入并提交注册密码页时才使用配置中的注册密码（默认 `Aa150010150010`）并保存密码。已有账号登录、2FA 重试和换绑优先使用已保存的真实密码；无保存密码的 passwordless 账号（Camoufox 链路）在登录密码页改走邮箱验证码登录，登录成功后按 `auto_set_password`/`auto_set_2fa` 配置补设密码与 2FA；换绑仍必须使用已保存的真实密码和已启用 TOTP。
- 注册密码和 2FA 是两个独立的可选分支，四种开关组合都必须可运行；密码分支不得为了前置判断查询 `mfa_info`，只有实际进入 2FA 分支时才读取 MFA 状态。判断账号是否有密码以真实 `password_status=enabled` 为准，`password_set_after_registration` 仅表示本次是否执行过补设操作。
- Session、2FA、套餐/Plus 和结构化错误使用统一业务结果契约，但协议 HTTP 与 Camoufox async page 只在 transport adapter 层保持差异。
- Cloudflare、人机验证和安全挑战只记录并停止，禁止自动绕过。Session 失效、网络临时错误和业务限流必须按 AutoRegister 的重试边界处理；不得把业务 429 当成可重复提交信号。

### 3.4 邮箱取件（唯一权威规则）

邮箱来源解析、邮箱验证码获取是唯一允许保留 AutoPhone 自行实现的部分：继续使用 `mac_overrides/mailbox_otp_service.py` 及其现有策略模式，包括来源解析、请求前基线、旧验证码排除、消息身份判断、时间过滤、轮询、重发和阶段隔离。两条链路必须统一调用该服务；浏览器驱动不得引入固定邮箱格式或另一套邮箱 provider。除这些邮箱取件边界外，不得自行设计另一套注册链路，不得为了兼容旧实现而保留与参考项目不同的主流程。

### 3.5 换绑

Free 账号换绑统一使用纯协议链路：无论账号来自哪条历史注册链路，都必须复用 AutoRegister 对齐的协议会话、Sentinel、password+TOTP 登录、`change_email` eligibility/begin/verify、新邮箱 OTP、换绑后新邮箱重登、Session 刷新以及套餐/Plus 资格查询。换绑不得打开、连接、复用或创建浏览器 Profile，也不得另行设计浏览器状态机。换绑只允许使用已有密码和已启用 TOTP 的完整 Free 账号；邮箱验证码按 3.4 使用 `mac_overrides/mailbox_otp_service.py` 的现有策略。

### 3.6 账号测活

- 快速测活：使用注册时保存的 `access_token`，通过执行时从共享健康代理池分配的代理向账号接口发起单次已登录查询判定存活（正常 / Token 失效 / 已停用 / 被出口或安全策略拒绝）；不重新登录、不收取邮件、不做额外出口 IP 预检。
- 深度测活：通过共享健康代理池分配的代理完整重新登录（OAuth → 邮箱 OTP / 密码 / 2FA → consent → callback）后用新 token 查询，并把新 access token 落库；可能收取一封邮箱 OTP。
- 测活不绑定账号原代理，每次执行都按 3.2 从现有健康代理池分配；403 或安全挑战页只判定为出口/服务端策略拒绝，不得判定为账号停用；结果（状态、时间、HTTP 状态、失败结构、套餐字段）写回邮箱池行的结果记录。
- 深度测活重新登录明确确认账号停用（与接码链路同一 `account_banned` 显式判定器）时，自动将该行从 Free 邮箱池删除；删除失败则标记为不可用。注册结果与诊断日志一律保留，不得随行删除。

## 4. 工程模块边界与数据隔离

### Free 工程模块边界

- Free 新建只允许 `protocol` 与 `camoufox`；不得新增 Remail 或恢复 Roxy 新建驱动。
- Camoufox 的可维护边界在 `mac_overrides/free_camoufox/`（contracts、transport、state machine、browser pool、debug artifacts、runner）；`free_camoufox_runtime.py` 只保留兼容 facade 和恢复层。
- Free 任务编排边界在 `mac_overrides/free_register/`（contracts、repository、scheduler、retry、worker、timing、manager）；`free_register_runtime.py` 只做兼容组合，不得把状态机、池管理、路由或日志继续堆回大文件。
- Free 持久化使用 `free_storage.py`/适配器提供的独立 SQLite；普通短信/OAuth 目录和数据库不得共享。换绑使用独立 `free_rebind.sqlite3`（或等价独立 repository），不得与注册任务表混用。
- 邮箱取件策略只能复用 `mailbox_otp_service.py` 的策略模式（见 3.4）；驱动不得另造 provider。
- 所有新诊断事件必须经过 `DiagnosticEventWriter` 写入 `DiagnosticStore`；`FreeLogStore` 只作为兼容 facade，不得创建私有日志格式或覆盖首个真实失败。
- 旧 `logs.json` 与 `task_logs/*.json` 只允许由 `free_log_migration` 在 Free 目录内幂等清理；不删除诊断库、任务结果、邮箱池、代理池或账号数据。
- 新增节点必须同步登记稳定代码、中文名称、重试规则、处理建议和 focused contract test。任何跨模块改动先定位首个真实失败节点，再做定向测试、完整测试和 `git diff --check`。
- 真实邮箱、代理、Camoufox 浏览器和安全挑战只允许在用户明确授权的单次验收中执行；静态测试或环境错误不得伪装为链路成功。任务创建的临时副本、临时目录和验证清单在本次任务结束前删除。

### 数据隔离与目录边界

- 普通短信/OAuth 与 Free 注册的数据隔离见 3.1；支付链接工具只使用 `${GPTPHONE_DATA_DIR}/payment_tools/`，网络诊断只使用 `${GPTPHONE_DATA_DIR}/network_tools/`，不得复用注册任务状态。
- 前端源代码放在 `frontend/src/`；页面通过 Vite 热更新访问（见第 9 节）。
- 不要提交 `data/`、`mac_runtime/`、`engine/`、`node_chain.dat`、`frontend/node_modules/`、`.zcode/`、缓存、导出文件或秘密。

## 5. 故障排查闭环

- 每次故障先用 `incident_id`、任务/批次/账号标识和时间线定位首个真实失败节点，先确认现有代码路径和参考项目调用顺序，再修改代码；不得仅凭最后一行泛化错误重复改同一处。
- 一个根因只做一次窄范围修复：先运行对应的定向测试，再运行完整测试和 `git diff --check`。没有新增证据时不得重复提交相同修补；连续两次同一节点失败必须暂停自动改动，整理证据并询问用户是否扩大范围。
- 真实邮箱、代理、浏览器和安全挑战只在用户明确授权的单次验证中执行；静态测试失败、网络不可用或权限不足不能伪装成真实链路成功。临时副本和临时数据目录由本次任务创建后必须在结束前删除。

## 6. 日志中心与故障审计

- 所有普通流程、Free protocol/Camoufox（以及历史 Roxy 只读记录）、Free 换绑、支付和网络诊断错误都必须产生可引用的 `incident_id`（日志中心显示为 `LOG-日期-短标识`）；排查优先使用日志 ID、稳定任务/批次/账号标识和时间范围，不要求人工翻阅自由文本日志。
- 新链路必须写入统一的结构化诊断事件，至少包含 `event_id`、`incident_id`、时间、链路、驱动、任务/批次、`node_code`、中文 `node_label`、结果、失败代码、可重试属性和脱敏处理建议；不得建立无法检索的私有日志格式。
- 诊断事件只追加，不原地覆盖；重试、浏览器关闭、代理释放、清理和进程恢复不得覆盖首个真实业务失败。清理或系统错误必须作为关联事件保存。
- 日志中心的诊断索引只保存脱敏事件和 HMAC/短指纹，不能成为普通流程与 Free 流程共享邮箱、代理、账号结果或运行状态的通道。
- 日志写入前和导出前都必须执行字段白名单与敏感信息脱敏；密码、Token、Cookie、验证码、手机号、TOTP Secret、OAuth 查询参数和代理凭据不得写入日志、诊断事件或导出文件。Free 代理池本地配置可按设置页需要保存并回传代理原文。脱敏失败时禁止把敏感信息写入日志或导出内容。
- 删除日志中心指定故障或清空全部诊断日志，只能删除 `${GPTPHONE_DATA_DIR}/diagnostics/` 下的诊断索引、事件和别名，不能删除邮箱池、代理池、账号结果、任务结果或 Free 数据。
- 每个日志 ID 必须可复制给 GPT；GPT 导出必须区分已确认事实、证据时间线、推导归因和未确认信息，不得把推测写成事实。
- 诊断索引必须报告自身的写入失败、丢弃、哈希完整性异常和存储健康状态；事件哈希断链时必须在日志详情中明确显示。
- 新增节点时同步登记稳定代码、中文名称、可重试规则、处理建议和测试；修改诊断契约时同步更新迁移、后端测试和前端类型。
- 日志中心不自动执行真实注册、真实代理测试、浏览器操作或安全挑战绕过。

## 7. 安全和诊断红线

- 未经用户明确同意，不得使用 `computer-use`、应用内浏览器、Chrome、Playwright 或真实浏览器操作。
- 不得在日志、任务结果或诊断索引中暴露邮箱密码、代理凭据、Cookie、OAuth URL 查询参数、授权头、access/refresh/ID/admin token、短信/邮箱验证码、手机号或 TOTP 秘密；Free 代理池相关公共 API 可按本机设置页回填需求返回代理原文（包括用户名和密码），其他敏感字段仍只能使用掩码或短指纹。
- 每个失败必须保留稳定节点代码、中文节点名称、HTTP 状态/服务商代码（如有）和脱敏的可操作原因；不能用"操作失败"或"failed"覆盖首个真实节点。
- 代理测试必须使用所选代理声明的协议，清除继承的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`，不得静默切换节点或回退到 Clash。当前主机 Clash Verge HTTP 代理是 `http://127.0.0.1:7897`；`12334` 不是有效配置，出现时必须追溯来源并修复。
- 测试和诊断不得覆盖用户运行数据；需要临时数据目录时使用临时目录，任务结束后删除由本次任务创建的临时副本。

## 8. 兼容和实现要求

- 覆盖恢复模块前先保存原方法，保持原有可调用签名（包括 keyword-only 参数），只做窄范围覆盖。
- 对不确定的恢复方法先查 `disassembly/index.json` 的对应切片，并在 Python 3.13 环境用 `inspect.signature` 确认签名。
- 保留已有配置字段和页面顺序，除非用户明确要求删除或调整。
- OTP 的请求基线、旧码排除和阶段状态必须按注册、已有账号登录、2FA enrollment 分开；取消、重试、清理不得覆盖原始终止原因。
- 真实邮箱注册或真实代理动作不是普通静态验证的一部分；只有用户明确授权时才可执行，且不得把失败的真实尝试伪装成成功。

## 9. 前端与发布验证

### 前端规则

- 前端源代码变化后必须运行类型检查（`cd frontend && npx vue-tsc --noEmit`）；前端页面默认通过 Vite 热更新访问（`frontend/vite.config.ts`：5173 代理 `/api` 到 18777），日常前端改动不构建、不更新 `frontend/dist/`。
- `frontend/dist/` 仅用于发布产物；仅在用户明确要求发布构建时执行 `npm run build` 用新产物覆盖 `frontend/dist/`。
- 运营台页面的筛选器、输入框、下拉框、分页和标签页统一使用紧凑的小尺寸控件（默认高度约 30–32px）；同一工具栏内不得出现明显失衡的大输入框与小标签页。表格操作按钮优先使用语义不同的图标，避免同一操作列重复使用相同图标；图标按钮必须提供 tooltip 和 aria-label。

### 版本

- Free 运行时版本统一在 `mac_overrides/free_runtime_info.py` 的 `FREE_RUNTIME_VERSION` 维护，与对应版本测试一起更新。

### 验证命令

后端验证：

```sh
mac_runtime/.venv/bin/python -m unittest discover -s tests -v
mac_runtime/.venv/bin/python -m py_compile mac_overrides/error_observability.py mac_overrides/web_gui.py mac_overrides/sms_runtime.py mac_overrides/task_progress.py
```

前端验证：

```sh
cd frontend
npx vue-tsc --noEmit
```

- 最后运行 `git diff --check`。除非用户明确要求，不要启动或重启 Flask 服务，也不要点击真实注册、短信、SUB2、Pixel、支付提取或代理测试动作。

## 10. 代码规范

本章是对现有代码事实标准的固化管理；标杆文件即规范的活样例。规则约束新增与修改的代码，存量欠账按 10.6 路线图单独排期，不要求一次性回改。

### 10.1 通用

- 新模块目标 <500 行，软上限 800 行；达到软上限必须在下一次触碰该模块时优先拆分。
- 禁止向既有大文件（`web_gui.py`、`web_routes.py`、`free_*_runtime.py` 等）追加新业务逻辑；兼容 facade 只减不增。
- 模块首行必须有英文 docstring（一句话职责说明）；代码注释与 docstring 一律英文，用户可见消息（日志摘要、错误公开消息、节点中文名）一律中文。
- 禁止 TODO/FIXME/HACK 注释和 `print()` 调试残留；诊断输出走第 6 节的结构化事件。
- 禁止新增 `globals()[_name] = ...` 式反射批量复制（`web_gui.py` 既有反射复制是历史例外）；新增导出必须显式登记。

### 10.2 Python 后端

- 每个模块 `from __future__ import annotations` + 现代注解语法（`str | None`、`dict[str, Any]`）；公开函数/方法签名必须完整注解（标杆 `mac_overrides/free_register/contracts.py`）。
- 值对象、快照、分类结果用 `@dataclass(frozen=True, slots=True)`（标杆同上）；带锁的会话/请求/运行状态上下文允许可变 dataclass，但禁止绕过方法在类外直接写字段（标杆 `auth_session_runtime.py` 的 `AuthSessionContext`）。
- 模块必须定义显式 `__all__`，只含公开名，不含 `_` 前缀私有名。
- 领域业务异常统一 `*Error(RuntimeError)`，携带结构化字段（code、status、retryable、diagnostic 等；标杆 `mac_overrides/error_observability.py`、`mailbox_otp_service.py`）；纯输入校验可直接 `ValueError`，同一模块不得为同类错误混用两种基类。
- try/except ImportError 双轨导入（包内相对导入 + 顶层脚本导入）是允许的既定兼容模式，fallback 分支加 `# type: ignore[no-redef]`。
- 禁止静默吞异常：`except Exception` 至少必须经现有诊断/日志通道留痕（遵守第 6 节字段白名单与脱敏），仅在"清理/遥测失败不得改变业务结果"的语义下允许捕获后继续。
- 覆盖恢复模块遵守第 8 节：保存 `_ORIGINAL_*`、窄覆盖、保持签名。

### 10.3 测试

- 统一 unittest（`unittest.TestCase`），文件名 `test_<被测模块名>.py` 与模块对应，跨模块契约/集成测试除外。
- 测试类命名 `<被测对象>Tests`；断言面向行为契约而非实现细节。
- 新增节点/契约同步登记 focused contract test（见第 4 节）。

### 10.4 前端

- 组件一律 `<script setup lang="ts">`，props/emits 用泛型类型形式；组件 PascalCase 多词命名。
- tsconfig strict 下禁止新增 `any`（含 `catch (error: any)`，用 `unknown` + 收窄替代）；存量 any 只减不增。
- 共享类型进 `frontend/src/types/`；`api/client.ts` 只保留端点封装与兼容再导出层（标杆 `types/free.ts` 的迁移模式）。
- `composables/` 只放含 Vue 响应式逻辑且以 `use` 开头的组合函数；纯函数一律放 `utils/`，文件顶部必须有英文 JSDoc 职责说明（标杆 `utils/datetime.ts`）。
- 样式用 `<style scoped>` + Element Plus CSS 变量；控件统一 `size="small"`；tooltip 统一 `:show-after="250"` + `placement="top"`；图标按钮必须提供 tooltip 和 aria-label（衔接第 9 节）。
- 禁止 `console.*`；禁止无引用的死组件、死导出（同文件内部消费的导出不视为死代码）。

### 10.5 提交信息

- 格式 `type(scope): 中文描述`；type ∈ feat/fix/refactor/docs/chore/test；scope 用既有用法（free、frontend、backend、sms、diagnostics 等）。
- 一次提交只做一个关注点；结构重构后单独 `chore(free)` 提交 bump `FREE_RUNTIME_VERSION`（见第 9 节）。

### 10.6 存量欠账路线图（已全部销账，2026-09-10）

原列欠账已按第 5 节闭环逐批完成；新欠账出现时按同样纪律另起批次。

- 大文件拆分批次（已完成）：`web_gui.py` 三段补丁拆为 host 委托模块（`web_gui_config_patches.py`、`web_gui_importer_patches.py`、`web_gui_codex_patches.py`，另拆配置生命周期 `web_gui_config_lifecycle.py`）；`free_camoufox_runtime.py` 6482→约 1230 行（页面交互 `page_interactions.py`、注册主流程 `browser_flow.py`、浏览器池与注册表 `browser_registry.py` 入 `free_camoufox/` 子包，facade 保留委托与 lazy `__getattr__` 兼容导出）。
- 后端 `except Exception: pass` 治理（已完成）：宽异常裸吞咽全部改为各模块 `_note_stderr`/`_note_quiet` 式最小留痕（仅异常类名与失败点标签，不泄敏感值）；窄类型（OSError/数值清洗/asyncio 取消惯例/delattr 幂等）语义正确予以保留。`sms_key_pool` ↔ `sms_provider_orchestration` 已抽 `_PooledSmsActivationMixin` 公共激活（真实行为分叉保持独立）；auth 四件套 `normalize_page_type` 单源 `auth_page_type.py`、`_safe_path` 语义化为 `_whitelisted_auth_path`/`_continue_url_path`。
- 前端 `any` 治理（已完成，src 下 any 口径为 0）：`Record<string, any>` 改 `JsonRecord`/精确类型（`DiagnosticsHealth` 等），表单接 `AppConfigForm`，emit 收窄；tsconfig `noUnusedLocals`/`noUnusedParameters`/`noFallthroughCasesInSwitch` 已开启；display 工具接入 `FreeMailboxRow`/`FreeTaskRow`。
- 每批治理必须先定位首个真实失败风险，做定向测试、完整测试和 `git diff --check`（见第 5 节闭环）。
