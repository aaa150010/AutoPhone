# AutoPhone 新功能开发指南（Add-a-Feature Handbook）

本文面向"要往 AutoPhone 里加一个功能"的开发者，按任务类型给出**必改文件清单**与推荐照抄的样板文件。项目规范总纲见根目录 `AGENTS.md`（第 10 章代码规范、第 4 章模块边界、第 6 章诊断要求）；模块职责一句话地图见 `BUSINESS_MODULES.md`。

通用纪律（每次改动收尾必须做）：

```sh
mac_runtime/.venv/bin/python -m unittest discover -s tests   # 后端全量（当前 ~2068 例，约 33s）
cd frontend && npx vue-tsc --noEmit                          # 前端类型检查
git diff --check                                             # 空白错误检查
```

测试文件命名 `test_<被测模块名>.py`，类名 `<被测对象>Tests`，统一 unittest。新增节点/契约必须同步登记 focused contract test。

---

## 1. 新增一个「节点」（node）

一个节点的登记分散在 **5 个后端注册表 + 2 个前端回退表**，缺一处就会出现"日志里是裸代码、界面没有中文名、重试规则错"的问题。

Free 节点照抄 `free_password_*` 系列的登记方式；普通（SMS/OAuth）节点照抄 `email_password` 系列。

| # | 必改文件 | 登记内容 |
|---|---|---|
| 1 | `mac_overrides/error_observability.py` → `NODE_LABELS` | 稳定代码 → 中文节点名 |
| 2 | `mac_overrides/error_observability.py` → `_ACTION_HINTS` | 按 error_code 的脱敏处理建议 |
| 3 | `mac_overrides/free_register_common.py` → `FREE_STAGE_LABELS` | Free 阶段中文名（Free 节点才需要） |
| 4 | `mac_overrides/free_failure_runtime.py` → `_ACTION_HINTS` | Free 失败投影的 action_hint |
| 5 | `mac_overrides/task_progress.py` → `STAGES` / `TASK_STATUS_STAGES` / `CHAIN_STATE_STAGES` | 实时进度展示与状态映射 |
| 6 | `mac_overrides/free_register/retry_policy.py` → `_BLOCKED_HTTP_STATUSES` / `_BLOCKED_MARKERS` / `_PRE_SUBMISSION_NODES` | 重试规则：前置提交节点（可复用邮箱）加入 `_PRE_SUBMISSION_NODES`；不可重试标记加入 `_BLOCKED_MARKERS` |
| 7 | 字段白名单 | 新诊断字段先进 `free_failure_runtime.py` 的 `FAILURE_KEYS` 与 `diagnostic_writer.py` 的 `_ALLOWED_FIELDS`（脱敏红线，见 AGENTS.md 第 6 节） |
| 8 | `frontend/src/utils/freeStage.ts` / `taskStageNodes.ts` | 后端缺标签时的 UI 回退标签 |
| 9 | `frontend/src/types/api.ts` → `TaskFailure` | node_code / node_label / retryable / action_hint 字段契约 |
| 10 | focused contract test | `tests/test_error_observability.py`（断言 NODE_LABELS 已登记）、`tests/test_free_failure_runtime.py` 等 |

诊断事件发射样板：`mac_overrides/free_register/manager.py`（构造 `DiagnosticEventWriter(diagnostic_store, context=LogContext(chain="free", workflow="register", driver="free"))` 后 `writer.record({...})`）；事件 dataclass 契约在 `mac_overrides/diagnostic_contract.py` 的 `DiagnosticEvent`。

## 2. 新增一个 API 路由

无 Flask 蓝图，三层结构：`web_routes.py`（装配元组表）→ `web_routes_sections.py`（按域 builder）→ 控制器模块。

- **普通域**（`/api/...`）：照抄 `mac_overrides/mailbox_mutation_routes.py`——提供 `routes()` 工厂返回 `(rule, endpoint, view_func, methods)` 元组组，在 `web_routes.py` 的元组表里 `*mailbox_mutation_routes.routes()` 展开合入；错误响应统一走 `route_failures.py` 的 `explicit_failure_payload(node_code, node_label, error_code, cause, http_status)`。
- **Free 域**（`/api/free/...`）：照抄 `mac_overrides/free_pool_routes.py`。
- 小型独立控制器样例：`local_config_routes.py`、`sms_balance_routes.py`、`runtime_info_routes.py`。
- 新页面若新增 SPA 深链路径，需同步 `web_routes_sections.py` 的 deep-link 列表（仅 `frontend/dist` 存在时生效）。

## 3. 新增一个前端页面 / 组件

- 页面：照抄 `frontend/src/pages/RemailOrdersPage.vue`；在 `components/AppShell.vue` 两处登记（`defineAsyncComponent` 导入 + 模板 `v-if="activePath === ..."` 分支 + `<el-menu-item index="/path">` 菜单项）。
- API 封装：`frontend/src/api/client.ts` 每端点一个具名导出函数（通用 `api<T>()` fetch 包装已有）；**类型不写在 client.ts**，放 `frontend/src/types/`（通用域 `api.ts`，Free/诊断域 `free.ts`），client.ts 只做兼容再导出。
- 设置区块照抄 `components/RemailSettingsSection.vue`；组合逻辑进 `composables/use*.ts`，纯函数进 `utils/`（文件顶部英文 JSDoc）。
- 规范红线（AGENTS.md 10.4）：`<script setup lang="ts">`、禁 `any`/`console.*`、控件 `size="small"`、tooltip `:show-after="250" placement="top"`、图标按钮必须带 tooltip 和 aria-label。

## 4. 新增一个配置项

三处必须同步，缺一处就会出现"后端存了、前端不显示/不归一化"：

1. 后端：`mac_overrides/free_register_config.py` 的 `DEFAULT_FREE_CONFIG` + `normalize()`（默认值、clamp、旧值迁移）+ `public()`（掩码，`SECRET_MASK`）+ `secret()`（明文按需读取）。
2. 前端默认值：`frontend/src/utils/freeConfigDefaults.ts` 的 `defaultFreeConfig()`。
3. 前端类型：`frontend/src/types/free.ts` 的 `FreeConfig`。

保存入口统一走 `free_config_routes.py` 的 `save_free_config_bundle`（先 normalize 校验再落盘，代理内容与配置同事务）。测试样板 `tests/test_free_config_routes.py`（掩码不覆盖、legacy 迁移）。结构性变更需 bump `mac_overrides/free_runtime_info.py` 的 `FREE_RUNTIME_VERSION`（与版本测试一起更新，见 AGENTS.md 第 9 节）。

普通运行配置（非 Free）走 `configuration_runtime.py` 的迁移器模式 + `local_config_routes.py`，前端接 `appConfigNormalize.ts` 的 `AppConfigForm`。

## 5. 新增一种邮箱来源 / provider

唯一基线是 `mac_overrides/mailbox_otp_service.py` 的策略模式（AGENTS.md 3.4 红线：浏览器驱动不得另造 provider）：

1. 写一个工厂函数（参考 `_url_source_factory`），组装 `MailboxHttpTransport`（代理/重试/超时策略见 `mailbox_transport.py` 的 `MailboxNetworkPolicy`）+ `MailboxUrlClient`。
2. `register_mailbox_source("<来源名>", factory)` 注册；消费端 `MailboxOtpService.__init__` 会按来源名自动实例化。
3. 取件 URL 探测细节在 `mailbox_pickup_runtime.py`，验证码提取在 `mailbox_code_parser.py`，Free 侧包装在 `free_mailbox_otp.py`。
4. 测试样板：`tests/test_mailbox_otp_service.py`。

## 6. 新增一种短信平台

分两档，摩擦差异很大：

- **低摩擦**：给已有平台加 key / 改默认 service —— 只改 `mac_overrides/sms_provider_runtime.py` 的 `SMS_PROVIDER_DEFAULT_SERVICES` / `SMS_PROVIDER_ALIASES` 登记表。
- **高摩擦**：全新平台适配器 —— 平台 HTTP 适配器类（`BaseSmsProvider`、`FiveSimProvider` 等）在恢复模块 `sms_providers`（`business_pyc/sms_providers.pyc`），不是可维护源码。需要按第 8 节覆盖规范在 mac_overrides 侧补适配器或新增窄覆盖（`web_gui.py` 现有 `_SMS_WEB.create_provider`/`_try_get` 覆盖是样板）。聚合注册表在 `sms_provider_orchestration.py` 的 `SmsProviderRegistry`（每平台一个 key pool），余额查询走 `sms_balance_runtime.py` + `sms_balance_routes.py`。测试样板：`tests/test_sms_web.py`（假 Provider 模式，不产生真实费用）。

## 7. 覆盖恢复模块（Python 3.13 运行时产物）

见 AGENTS.md 第 8 节。要点：先保存 `_ORIGINAL_*`；窄覆盖保持原签名（含 keyword-only）；不确定的恢复方法先查 `disassembly/index.json` 对应切片（`tools/disassembly_query.py`）并用 `inspect.signature` 确认；patch-host 模块（`web_gui_*_patches.py`、`web_gui_mailbox_wait.py`）的每个函数第一个参数是 `host`（web_gui 模块），内部经 `host.<name>` 晚绑定读取，保证测试按 `web_gui.<name>` 打补丁的语义不变。

## 8. 验证清单（提交前）

- [ ] 定向测试（改哪个模块跑哪个 `tests/test_<模块>.py`）→ 全量 `discover` → `git diff --check`
- [ ] 动了前端：`npx vue-tsc --noEmit`；日常前端改动**不**构建 `frontend/dist/`（仅发布时 `npm run build`）
- [ ] 新节点五表 + 两前端回退表 + focused test 齐全（本指南第 1 节）
- [ ] 日志/诊断无敏感字段（密码、Token、Cookie、验证码、TOTP、OAuth 查询参数、代理凭据）——白名单与脱敏必须先行
- [ ] 提交信息 `type(scope): 中文描述`，一次提交一个关注点
