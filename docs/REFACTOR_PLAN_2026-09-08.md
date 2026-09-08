# AutoPhone 整体重构优化总计划（全量审查版）

- 审查基线：commit `5735ab3`（2026-09-08）。
- 覆盖范围：mac_overrides 全部 184 个 Python 文件（约 9.5 万行）、frontend/src + tests 84 个文件（约 1.3 万行）、tests/ 127 个文件（约 5.9 万行）、tools/、deploy/、根文档。审查方式：18 个并行分区 agent 逐文件通读，分区清单经脚本验证 100% 无遗漏、无重复。
- 执行约定：每批先跑定向测试 → 全量 `unittest discover` → 前端 `vue-tsc --noEmit` → `git diff --check`；一次提交只做一个关注点；结构重构后单独 `chore(free)` bump `FREE_RUNTIME_VERSION`；全程遵守 AGENTS.md（尤其第 5/7/8/10 节）。

---

## 第 0 批：P0 缺陷修复（正确性风险，最先做，不依赖任何前置）

审查发现 8 个真实缺陷。其中 4 个是"触发即 NameError"级别，疑为历史重构中丢失常量定义。

| # | 文件 | 问题 | 修复 |
|---|------|------|------|
| 0.1 | `mac_overrides/chatgpt_plan_gate.py:369` | `_TRANSPORT_TOKEN_ATTRS` 未定义，`_transport_token` 被调用即 NameError（AST 确认） | 补常量定义 |
| 0.2 | `mac_overrides/chatgpt_plan_gate.py:399,529` | `_TRANSIENT_EXCEPTION_NAMES` 未定义，生产异常路径会把网络错误掩盖成 NameError | 补常量定义 |
| 0.3 | `mac_overrides/chatgpt_plan_gate.py:535` | `time` 未 import，重试延迟 `time.sleep` 会 NameError | 补 import |
| 0.4 | `mac_overrides/free_account_service.py:761` | `MANUAL_SUBMISSION_GRACE_SECONDS` 未定义，2FA grace 分支触发即 NameError | 定义常量（对齐 free_account_otp 的 2.0s 语义） |
| 0.5 | `mac_overrides/free_plan_check.py:346` | 代理无效时静默直连 chatgpt.com，违背"仅用绑定代理"契约（对照 free_live_check.py:601 是 raise） | 代理缺失/无效 fail closed 抛 FreeRegisterError |
| 0.6 | `mac_overrides/sms_provider_orchestration.py:901` | 调用不存在的 `self.registry._log(...)`，HeroSMS 前置取消告警永不落地 | 改用 `self.logger(...)` |
| 0.7 | `mac_overrides/sms_network.py:265` | 代理路径 `verify=False`，携带 API Key 的请求可被代理侧中间人窃取 | 默认 verify，加配置开关 |
| 0.8 | `tests/test_free_register_runtime.py:754` | `if expected.is_file():` 条件断言文件缺失时永真通过 | 改无条件断言 |

验证：0.1–0.4 用 `inspect.getattr_static`/最小 import 冒烟 + 对应定向测试；0.5 对照 free_live_check 行为；0.7 需要真实代理场景的仅做静态验证，不执行真实代理动作（第 7 节红线）。

## 第 1 批：诊断/脱敏内核统一（横切面最大，先做避免后续批次冲突）

1. `sanitize_failure_detail`（error_observability.py:188）与 free_failure_runtime.py:563 的 incident-ID 保护双标准合一；修复 `LOG-20260908-…` 日期段被手机号正则改成 `<phone>` 的 bug。
2. 合并 NODE_LABELS 重复键（error_observability.py:62/77）与 `_CHAIN_NEXT_NODE` ↔ `task_progress.CHAIN_STATE_STAGES` 两套映射（`MFA_OTP_VERIFIED` 指向不一致，会漂移失败归因）。
3. failure_secrets.py 收集环节静默吞异常（L18/31/53）：失败时计数/留痕，否则精确脱敏静默失效。
4. diagnostic_writer preserve_id 白名单补 JWT/token 形状排除（L124-131）。
5. mailbox_redaction.py:73 非 ASCII 分支大小写变体漏脱敏。
6. 结果文件名白名单：result_persistence_runtime.py:49 email 进文件名前净化 `[A-Za-z0-9._-]`。

## 第 2 批：auth/openai 域公共 helper 收敛（衔接 sess_24169517 已做的 efec296，完成 10.6 该条目的后半）

1. 统一网络错误分类三套：auth_connectivity_runtime `_CONNECTIVITY_RULES` / connectivity_diagnostics `_failure_reason` / openai_quota_runtime `_network_error_message` → 单一 reason_code 体系。
2. HTTP 状态提取器 6 处、page_type 提取器 4 处收敛（auth_session/auth_request/plan_gate/connectivity_diagnostics/phone_binding/openai_quota）。
3. TOTP secret 归一化三写（chatgpt_totp / oauth_mfa_runtime / mailbox_password_url_rows）收敛到 oauth_mfa_runtime。
4. `PHONE_PAGE_TYPES` 双写（auth_challenge_runtime:33 / auth_request_runtime:40）移入 auth_page_type.py。
5. `_response_continue_url` 双实现（free_protocol_helpers:219 / free_account_payload:100，strong_keys 不一致）收敛。
6. mfa_retry_runtime:133 `verify_fn` 异常路径补 try/finally 清理 `_gptphone_totp_secret`（secret 滞留）。
7. keychain_runtime:96 `get_or_create` 区分 errSecItemNotFound 与访问失败，避免 keychain 锁定即静默轮换密钥。
8. chatgpt_plan_gate.py 清理死方法 `_cached_token`/`_transport_token` 及 `evaluate_sms_binding` 死分支。

## 第 3 批：Free 编排域迁移收官（10.6 主线）

1. free_register_runtime.py（2268 行）：`_worker` 状态机（~440 行）、`import_mailboxes`、`secret`/`temporary_totp`、租约回调迁入 free_register/ 子包（worker.py/manager.py 已存在）；runtime 收敛为 facade。
2. 处置 free_register/ 子包未接入的组合件：scheduler.py 整模块死代码、worker.py 的 `except BaseException` 吞 KeyboardInterrupt、manager.build_manager_components 仅测试引用——接入或删除，消除双轨。
3. 删除确认死代码：free_register_store.py:697-783 被 L1062 覆盖的 legacy FreeProxyPool（含 verify=False 旧探测）、free_register_scheduler.py:146-172 `_verify_pre_registration_proxy` 链、free_register_config.py:295-306 死的 normalized_selection、free_live_check.py:639 `_observe_proxy`。
4. 修复 free_mailbox_code.py:30 remail 快捷取码断链：runtime_info_routes.py:231 补传 source/email/token；provider 补 close()；pickup URL token 不落 sample 库。
5. 超大文件拆分（按 10.6 lazy `__getattr__` 模式）：free_protocol_flow `_run_once`（580 行）按页面状态拆；free_protocol_runtime `_run_protocol`（580 行）按 continuation 拆；free_proxy_store 拆 probe/lease/pool；free_protocol_bootstrap 拆 session_identity/preflight_warmup。
6. 补齐注解隐患：free_register_bands.py:873 `Sequence`、free_register_startup.py:505 `Future` 未导入（`get_type_hints` 即 NameError）。
7. free_priority_executor.py:61 shutdown join 加超时。
8. free_account_service.py 抽出 browser re-auth 四组重复闭包 helper（stage/failure/navigate/otp-prepare）；`"unsupported OTP callback signature"` 字符串哨兵改专用异常。

## 第 4 批：邮箱域

1. 断开 mailbox_url_runtime ↔ mailbox_request_runtime 循环依赖（依赖注入或合并 state 类）；url_runtime 从 pickup_runtime 导入的 11 个私有符号建公共 API 或下沉共享解析模块。
2. mailbox_request_runtime 的 runtime_* 六函数与 mailbox_otp_service 双轨收敛到 otp_service 单轨，统一诊断 schema。
3. mailbox_otp_service.py（1319 行，唯一基线）内部拆层不破边界：传输件（MailboxHttpTransport/network policy/registry）外移 re-export，`__all__` 面不变；wait_code 对 retryable scan 错误改轮询内容忍（L844 与 prepare L735 语义对齐）。
4. mailbox_admin.py（1237 行）拆出 ~250 行 list_mailboxes 行装配器；reveal_password/totp/url 增加无明文审计日志。
5. mailbox_state_runtime 三段 mutation 模板抽公共 `_mutate_rows`。
6. mailbox_otp_service wait 轮询内补建基线（prepare 基线失败后旧码排除只剩 120s 时窗）。

## 第 5 批：并发/批次域

1. **抽取统一门控基类**：`ProxyProtocolGate` / `AdaptiveConcurrencyGate` / `AdjustablePhaseGate` / `InflightAdmissionGate` 四份 Condition-admission 复制（active/waiting/pause_until/success_streak/_stopped/_notify）下沉 `ThresholdGate` 基类，子类填策略钩子。
2. importer_scheduler.py：`with importer.lock:` 375 行临界区内的 batch_manifest.reserve（fsync）与 executor.submit/deepcopy 移出锁外；~10 处真静默 `except: pass` 收敛为 `_best_effort` helper。
3. run_batch_runtime.py 持久化降频（每次成员状态变更全量 fsync → 防抖/追加）。
4. transport_lifecycle.py 进程级 `_CLOSE_LOCK` 串行化 + session.close 无超时 → 按实例加锁/加护栏；诊断段拆 process_resources.py。
5. adaptive_concurrency `finished_tasks` 批次内无界增长 → 批次结束清理。

## 第 6 批：SMS/SUB2 域

1. sms_key_pool ↔ sms_provider_orchestration 同构统一（10.6 点名）：共享池基类 + 单一 PooledSmsProvider，预计净删 250+ 行；`query_key_pool_balances` 并回 SmsKeyPool（balance_runtime 直挖 pool 私有成员）。
2. SMS 域 29 处 `except: pass` 定向治理（orchestration 4、order 3、guard 3、sub2_update 3、binding 3、key_pool 2、sub2 2、runtime 1、network 1、sms_web 6）：回调类补留痕，解析回退类加注释。
3. `_as_float`/`_candidate_value` 三写收敛到单一 primitives 模块。
4. sub2 血缘双实现收敛：mailbox_sub2_results.latest_sub2_accounts_by_email 并入 mailbox_result_index 快照为唯一实现。
5. 死代码：sub2_update_runtime 死依赖 resolve_group/assert_group、sub2_runtime `_export_safe_int`、sms_cost_history `_directory_signature`、sms_provider_orchestration `_resend_attempted`、死导入（sms_runtime 8 个、key_pool `re` 等）。
6. sms_network 三个兼容 wrapper（`_candidate_route` 等）确认 monkeypatch 消费方后收敛。

## 第 7 批：存储/代理域

1. free_storage 六个 mixin 每文件 ~110 行双轨 import 带（合计 ~660 行）收敛为单一 import seam。
2. free_storage_adapters.py（1415 行）拆 mailbox/task/proxy 三个适配器模块；删除 `_proxy_url_from_row`；N+1 resource_leases 查询改批量。
3. 多池时代 API 面清算：`DEFAULT_PROXY_COUNTRY/GROUP`、`infer_country`、`normalize_country/group`、`bind/import` 的 country/group 形参移入显式弃用兼容层。
4. free_proxy_parse/health 死代码（`_EXIT_VERIFICATION_NODES` 空集、TLS 分支冗余）；`_exception_text`/`_exception_chain` 收敛。
5. 统一 atomic_write 双实现（configuration_runtime fsync 版 vs free_register_common 版）。
6. configuration_runtime.py:528 `127.0.0.1:7897` 硬编码回退改显式配置（合规收口，集中为单一常量）；`local_config_from_runtime`/`merge_local_config` 公共管线抽取；LocalConfigRuntime 13 依赖拆 secrets/migration/defaults。
7. free_proxy_bridge `allow_reuse_address` 设置时机无效修复；`free_proxy_chatgpt` 硬编码 `proxy_country: "US"` 确认语义。

## 第 8 批：诊断存储与通知

1. diagnostic_store.py（1496 行）拆分：root-cause 选择、search/export 各自成模块。
2. diagnostic_store `_safe_message` 前置 incident-ID 保护（同第 1 批主修复）；key 文件读取失败（L517）与"文件不存在"区分并审计。
3. FreeFailureRuntimeMixin 持久化段移出 free_failure_runtime.py；FreeLogStore legacy JSON 分支抽独立 adapter（生产已 `legacy_projection=False`）。
4. run_notifications.py（1200 行）拆 message_render + coordinator；notification_queue 50ms 忙轮询改阻塞等待；free_notifications SMTP 配置每次 send 重读。

## 第 9 批：web_gui/web_routes 拆分（10.6 已排期的三段搬迁执行）

1. web_gui.py（4356 行）按 10.6 行号段拆：importer 生命周期/持久化段（1559–2316）、codex 传输段（2515–3296）、配置段（686–1006），沿用 lazy `__getattr__`；显式化 `__all__`，删除 `_mask_secret`/`_local_secret` 死代码。**注意：工作区已出现 web_gui_config_patches.py / web_gui_importer_patches.py 未跟踪文件，动手前先与 sess_24169517 会话确认是否即该项工作。**
2. web_routes.py（1586 行）按既有 Controller 模式拆 Remail/Sub2Export/FreeStart 三个 Controller。
3. **凭据回填端点防护对齐**（安全项）：free_pool_routes 的 `/api/free/secrets`、`/api/free/mailboxes/format`、`/api/free/totp` 加 parser-sample 同款 loopback+confirm 防护；web_routes `api_remail_profile` 字段白名单裁剪（Key 元数据不裸透传）。
4. helper 去重：`_call_log`、`_safe_int`、`_mailbox_proxy`/`_latest_code_status`、`_accepts_keyword`；route_failures 死导出 `failure_payload`/`with_failure` 删除。
5. sms_web.py（1208 行）拆 lease lifecycle；legacy_ui.py HTML 注入抽资源常量。

## 第 10 批：camoufox 子包 + 邮箱 API 适配

1. `__all__` 私有名清理（debug_artifacts `_DebugTrace`、transport `*_LEGACY_FUNCTIONS` 11 个、state_machine `_browser_flow`、browser_pool 7 个、selectors 1 个——10.2 偏差统一收口，兼容走 `__getattr__`）。
2. fail-closed 脱敏正则双写（debug_artifacts `_redact_fallback` / transport `_fail_closed_snapshot_text`）下沉 debug_redaction。
3. free_mailbox_otp 直接 `from .free_camoufox.deadline import`（现复制 helper，注释声称防环但无环）。
4. remail_api/online_mailbox_runtime HTTP 重试/头样板收敛；contracts `_mask_email` 恒等改名；dead 载荷（`TransportOperation`、`write_json_atomic`、`sync_manual_prompt`、`MailboxLeaseConflict`）处置。
5. remail 分支 `import json` 位置、`plain_mailbox_rows.plain_password_identity` 红线注释。

## 第 11 批：前端

1. 修 FreeMailboxPool.vue:649 测活 mode 误塞 driver 字段导致弹窗标题显示"历史链路"（真实 UI 缺陷）。
2. 展示单一来源：新建 utils/driverDisplay.ts（driverLabel 五处拷贝：FreeTaskLogDialog/freeTaskDisplay/freeLiveDisplay/LogCenterPage/MailboxParserSamplesPage）；terminalStatuses 三处组件拷贝统一从 taskResultViews 导出；MailboxTable/TaskResultsPanel 死 CSS、FreeMailboxPool 死 metrics 字段。
3. FreeRegistrationPage ↔ FreeRegisterSettingsSection 两份 defaultConfig 已漂移（缺 tls/remail 字段）→ 抽 utils 单一来源。
4. useAppController 拆分：secrets 加载独立、轮询复用 usePolling；save 校验/secret 合并补 node:test（当前 0 覆盖）。
5. client.ts：`api<T = unknown>` 默认 + 补 4 个端点返回类型；6 个零引用死端点处置；useMailboxRowActions 3 个内联端点迁入 client.ts。
6. 可访问性：MailboxTable 密码/2FA 掩码按钮补 aria-label；MailboxActionMenus emits 改泛型标注式；RunOperationBar 显式导入图标、size="small" 对齐。
7. package.json 补 `typecheck` 脚本；tsconfig include 加 tests/；MailboxPage props 驼峰/kebab 统一。

## 第 12 批：测试体系

1. tests/test_web_gui_security.py（4652 行）拆分 + 提取 `patch_module_attr` 上下文管理器（~100 处 try/finally 样板）。
2. 手工模块全局补丁改 mock.patch：test_web_gui_sub2_binding、test_web_gui_result_persistence、test_free_camoufox_contracts（断言失败即泄漏补丁）。
3. 删除 test_chatgpt_plan_gate.py 13 个 @skip 死测试，补 5 个零覆盖纯函数。
4. 建 tests/support：FakeClock 五份、FreeManager fake 十余份、codex_oauth_chain stub、mailbox client 常量块收敛；忙等轮询统一 `await_idle` 助手（30+ 处 time.sleep）。
5. 公开契约缺口补测（P1 级集中批）：free_failure_runtime ~15 个 sanitize/merge 函数、mailbox_state_runtime 删除/恢复/批量元数据、sub2 导出 payload、free_pool_routes.import_free_proxies、notification_runtime.snapshot_ledger、sms_web adapter_complete/configure_pool/cancel_active_lease、RemailClient 错误路径、importer_scheduler.ObservedPhaseGate、configuration_runtime.LocalConfigRuntime 等。
6. 修正两处"测试名与断言相反"（test_free_live_check:121、test_diagnostic_writer:113）；test_free_read_routes 跨文件借壳 fixture 提为独立 builder。

## 第 13 批：文档/工具收尾

1. tools/recover.py:160 不再整体覆写 BUSINESS_MODULES.md（改写独立清单）——重跑恢复即抹掉手工文档的正确性风险。
2. 文档去同步：BUSINESS_MODULES.md/AGENTS.md 删除已移除的支付工具章节；README 删除 `/accounts` 路由与 6 个已删除模块的验证清单；README_运行说明.original.md 加"历史文档"横幅。
3. 脱敏：AGENTS.md 默认注册密码明文、README 个人 QQ 邮箱移除。
4. tools 四模块补 `__all__`；install_camoufox_runtime 静默 except 补 stderr 留痕。
5. deploy/token-tool-mailboxes 登录限速按 X-Forwarded-For（仅信内网 Caddy）；requirements Flask 版本注释。

---

## 横切验证清单（每批收尾执行）

```sh
mac_runtime/.venv/bin/python -m unittest discover -s tests -v
cd frontend && npx vue-tsc --noEmit
git diff --check
```

涉及 free 行为的批次另跑对应 focused contract test；结构重构批次 bump `FREE_RUNTIME_VERSION` 单独提交。

## 风险与协作注意

- **sess_24169517 仍在活跃提交**（本轮审查期间 HEAD 从 efec296 前进到 5735ab3，且 web_gui 拆分文件已在工作区出现）。动手前必须以最新 HEAD 重新核对受影响文件，任何批次开工前 `git pull`/`git log` 确认基线。
- 第 0 批的 4 个 NameError 常量缺失可能正是该会话进行中的工作，动手前先确认未与其撞车。
- 第 7.6（7897 回退）与第 0.7（verify=False）涉及运行行为变更，改动幅度需用户确认默认值取向。
- 真实邮箱/代理/浏览器动作不做；全部验证为静态与单测级别。
