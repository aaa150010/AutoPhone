# 全库复审合并清单(基线 70cfd0f,6 个并行审查 agent 收集)

上轮 14 批计划(基线 5735ab3)中已由批次 1-10 完成的项已剔除;以下为当前 HEAD 仍存活的问题,按修改分组(文件互不重叠,可并行)。

## 组A: auth 域 P0(执行 agent A)
1. chatgpt_plan_gate.py — `_TRANSPORT_TOKEN_ATTRS`(L369 用)/`_TRANSIENT_EXCEPTION_NAMES`(L399 用)未定义、`time` 未 import(L537 time.sleep)。三处 NameError 藏在零调用的死 retry 链里。修法:补齐符号定义(常量按既有 setattr 属性名对齐、transient 集合按 requests/httpx 异常名),补 `import time`;删除纯死方法 `_cached_session`/`_cached_token`/`_token_from_mapping`/`_cached_session_status`/`_transport_token`(零调用);删除 `evaluate_sms_binding` 永假的 decision raise 检查(计划 2.8 点名);同步删除 tests/test_chatgpt_plan_gate.py 的 13 个 @skip 死测试及其专属 harness `_run_until_allocation`。
2. keychain_runtime.py:96-124 — `get_or_create` 不区分 errSecItemNotFound(44)与 keychain 锁定/拒绝:锁定时走 `add-generic-password -U` 会覆盖现存密钥 → checkpoint 永久无法解密。修法:仅 returncode==44 才创建;returncode==0 但 base64/长度非法时记 stderr 留痕并报错;其余非零码 raise(带 stderr 摘要),绝不执行 `-U` 覆盖。
3. mfa_retry_runtime.py:133-141 — `verify_email_totp_with_one_window_retry` 写入 transport 的 `_chatgpt_totp_secret/_gptphone_totp_flow` 等四属性在 verify_fn 抛异常时滞留(对照 chatgpt_totp.patched_verify_mfa_otp 的 except BaseException 清理)。修法:包 try/except BaseException → 清理 + raise;补一个 verify_fn 抛异常的定向测试。
4. tests/test_free_register_runtime.py:755 — `if expected.is_file():` 包住 assert 的永真断言,改为 `@unittest.skipUnless(expected.is_file(), ...)` + 无条件断言。

## 组B: GUI 域 P0(执行 agent B)
1. web_gui_importer_patches.py:168-169,272-275 — `_CURRENT_TASK_ADMISSION`/`_CURRENT_INFLIGHT_GATE`(含 finally/except 清空)写入了 patches 模块自身全局,而 web_gui.py:370/410/1326/2172/2285 的 getter 读的是 web_gui 模块全局 → 永远 None。修法:改为 `host._CURRENT_... = ...`。
2. web_gui_codex_patches.py:629 — `globals().get("_CURRENT_INFLIGHT_GATE")` 同样读错模块 → `staged_pipeline` 恒 False。改 `host._CURRENT_INFLIGHT_GATE`。
3. web_gui.py:1297-1304 — `_real_headers` 同模块双定义,第一份被第二份静默覆盖;删除第一份死定义。
4. sms_provider_orchestration.py:905 — `self.registry._log(...)` 在 SmsProviderRegistry 上不存在(运行时验证)。改用存在的日志通道(对照本模块既有 self.logger / pool._log 模式,选语义最贴近的)。
5. sms_provider_orchestration.py:208/428/559 — `SMS_PROVIDER_DEFAULT_SERVICES` 使用但未导入(当前靠短路侥幸不炸)。补双轨导入;顺带清理本模块 10 个 imported-but-never-used 符号(HeroSmsCancellationDeferred、SECRET_MASK、_StaleSmsPreflight 等,AST 确认零引用)。
6. free_storage_schema.py:167 — 裸 `staticmethod` 独立表达式死语句(下一行才是真 @staticmethod)。删除。
7. free_storage_tasks.py:220-222 — `save_task` 的 ROLLBACK 未像同文件另两处包裹 `except sqlite3.OperationalError`,对齐写法。
8. web_gui_importer_patches.py:329-330 — `if not ...close_task(...): ...close_task(...)` 连打两次疑似笔误;读上下文确认语义后改注释明确重试意图或删除第二次调用。
9. web_gui_importer_patches.py:663-666/700-701、public_state_runtime.py:729-731 — 三处留痕注释文案与实际分支不符(密码损坏路径写成 relogin、connectivity 写成 phone),修正文案。

## 组C: 诊断脱敏域(执行 agent C)
1. error_observability.py sanitize_failure_detail — `_PHONE_RE \d{8,15}` 无 incident 保护,实测把 `LOG-20250908-AB12CD34`、批次号 `20250908-1122` 改成 `<phone>`(store 侧二次脱敏绕过 writer 侧 _FAILURE_INCIDENT_RE)。修法:在 phone 正则前先保护 `LOG-\d{8}-[A-Za-z0-9]+` 与 `\d{8}-\d{4,6}` 形态(占位回填),与 free_failure_runtime 语义对齐;加定向测试。
2. diagnostic_store.py:517-534 `_load_key` — key 文件存在但读失败(OSError)或长度不足时静默重建并覆盖 → 全部历史指纹失效、hash 链全体 failed。修法:仅文件不存在时生成新 key;读失败/长度不足保留旧文件、递增写失败计数并在 health() 暴露;加定向测试。
3. error_observability.py:62,77 — NODE_LABELS 重复键 `free_existing_login_otp`(后者静默覆盖前者);保留 L77 语义(等待已有账号登录验证码),删除 L62 或改键,确认无消费方依赖 L62 文案。
4. error_observability.py:154-175 `_CHAIN_NEXT_NODE` 与 task_progress.py:112-133 `CHAIN_STATE_STAGES` 双表漂移(`MFA_OTP_VERIFIED` 指向不一致)。修法:error_observability 删除自有 `_CHAIN_NEXT_NODE`,改引用 task_progress.CHAIN_STATE_STAGES(task_progress 归本组改)。
5. result_persistence_runtime.py:49 — 结果文件名 email 仅替换 `@`,`/`、`..` 可路径逃逸。修法:email 白名单化 `[A-Za-z0-9._-]` 再拼文件名。
6. diagnostic_store.py:105-107 vs diagnostic_writer.py:109-111 — 两套同名 `_safe_id` 语义相反(逐字符过滤 vs 整体拒绝);统一为 writer 版整体拒绝语义或明确各自契约,以不影响既有事件 ID 为准。
7. tests/test_diagnostic_writer.py:96-113、tests/test_free_live_check.py:107-121 — 两个"名 masks 断言直通"的测试:行为是产品有意的(display-safe email 豁免),把测试名改为与断言一致(`..._preserves_display_safe_email` 等),不改变生产行为。

## 组D: 安全红线 + Free 域(执行 agent D)
1. sms_network.py:266 — `isolated_sms_get` 代理路径硬编码 `verify=False`,经 web_gui monkeypatch 覆盖全部 SMS 平台余额/取码调用(API Key 可被代理 MITM)。修法:默认校验 TLS,新配置键 `sms_tls_verify`(local config,默认 true)关闭路径仅显式配置;同步 web_gui.py 若需接线则只加配置读取一行。注意:web_gui.py 归组B——本项在 sms_network.py 内加配置读取(自读 local config 或经传入参数),不改 web_gui.py,避免冲突;若必须动 web_gui.py 则只允许追加一行配置读取并与组B 的改动区(1297-1304)无行冲突。
2. free_proxy_store.py:851/860/884/899、free_register_store.py:739 — 代理探测 `verify=False` 统一收口为模块级常量 `_PROBE_TLS_VERIFY = False`(探测目标固定+指纹校验,风险低于 SMS,保持 False 但单点管理并注释理由)。
3. web_routes_sections.py:859-863(api_remail_profile)/894 附近(api_remail_wallet) — Remail 上游响应无白名单透传。修法:按 Remail Open API 文档字段显式挑选(profile: 订单状态/配额类字段;wallet: 余额字段),未知字段不透传;禁止把 Key/serviceToken 写进响应。
4. web_routes_sections.py:1310-1314 — SUB2 导出 model_mapping 硬编码 5 个模型名。提为模块级常量 `SUB2_EXPORT_MODEL_MAPPING` 并注释维护点。
5. free_rebind_runtime.py:949 — 新邮箱重登失败仍归因 `free_rebind_login_old`。提取 login 阶段参数区分 old/new;新增节点码 `free_rebind_login_new` 须同步登记 error_observability NODE_LABELS?——否,error_observability 归组C。改为:节点中文名直接在 FreeRebindError 的 label 参数给出,不新增全局 NODE_LABELS 键(若该节点注册表必须登记则报告并跳过,留待与组C 合并后处理)。
6. free_rebind_runtime.py:52-53 vs free_rebind_storage.py:34-37 — `ACTIVE_REBIND_STATUSES` 双定义且值分叉(runtime 不含 reserved)。修法:runtime 改从 storage 导入(含 reserved),使 `_recover_interrupted_tasks` 能恢复 reserved 行;加定向测试。
7. free_rebind_storage.py:139-151 — 死函数 `_mask_email`/`_mask_url` 删除。
8. free_rebind_runtime.py:554-591 vs 659-688 — `_source_rows`/`_source_context` 双份源账号快照逻辑收敛为 `_source_snapshot(row_id)` 单实现,行为逐字保持。

## 组E: 前端 + 工具文档(执行 agent E)
1. FreeMailboxPool.vue:650 — 测活日志弹窗把中文模式标签塞进 `driver` 字段导致标题"历史链路"。修法:去掉 driver 赋值(空值走 FreeTaskLogDialog 的 'Free' 兜底),模式已由 stage 体现。
2. FreeRegistrationPage.vue:45-58 与 FreeRegisterSettingsSection.vue:12-26 — defaultConfig 双副本漂移(页面版缺 proxy_tls_verify 等 7 字段)。抽 `defaultFreeConfig()` 单一来源到 utils/(以 SettingsSection 版字段并集为准),两处引用;顺带抽 `stripLegacyFreeConfigDraft` 收敛三份 roxybrowser 字段清理逻辑(quickRunConfig 漏删 proxy_selection.roxybrowser 一并修复)。
3. client.ts — 删除 8 个零引用端点(getFreeCamoufoxDebugState/getRemailProfile/getFreePlanCheckState/importFreeProxies/updateFreeProxyGroup/deleteFreeProxyGroup/openManualVerification/getMailboxParserSampleHealth);`api<T = any>` 默认改 `unknown` 并修调用处。
4. driverLabel 5 份拷贝 → utils 统一 `freeDriverLabel(value, emptyFallback)`(freeTaskDisplay/freeLiveDisplay/FreeTaskLogDialog/LogCenterPage/MailboxParserSamplesPage);terminalStatuses 3+1 份 → taskResultViews 导出 `TASK_TERMINAL_STATUSES` 常量,三组件引用(以 taskResultViews 含 cancelled 的版本为准,其余组件语义核对)。
5. main.ts — 删除 Element Plus 图标全量注册循环(组件均已显式 import;若有模板全局用图先补显式 import)。
6. package.json 加 `"typecheck": "vue-tsc --noEmit"`;tsconfig include 加 `tests/**/*.ts`(保留 allowImportingTsExtensions)。
7. 死 CSS/死代码: MailboxTable.vue:373-374 `.mailbox-operation-cell`、FreeRegisterSettingsSection.vue:361/381 `.proxy-selection-grid`/`.table-subline`、FreeMailboxPool.vue:204-214 空行、appConfigNormalize.ts stableValue 去 export、runtimeCapacity.ts(src 零引用,连测试一起删——先再确认)。
8. MailboxTable.vue:170,188 — `row.quota_5h?.remaining_percent > 0` 对 null 恒 false,改 `Number(...) > 0` 并区分 null。
9. tools/recover.py:160 — 不再整体覆写 BUSINESS_MODULES.md:改为仅替换自动生成清单标记区段(文件无标记则写到新文件并提示)。
10. tools/install_camoufox_runtime.py:74-76 — 内层静默 except 补 stderr 打印。
11. README.md:341-347 — 验证清单删除已不存在的 batch_upload/pixel/nv 三组条目。

## 组F: 邮箱/SUB2 死代码与双轨(执行 agent F)
1. mailbox_request_runtime.py:191-239 — `runtime_*` 六函数是 mailbox_otp_service 六个同名函数的死双轨(运行时全走 service 版)。删除六函数;mailbox_url_runtime.py:784-803 尾部 import 仅保留 `MailboxRequestState`;mailbox_otp_service.py:1254-1258 legacy fallback 兜底段一并删除。剪断 mailbox_url_runtime ↔ mailbox_request_runtime 回环后跑 mailbox 全部定向测试。
2. sub2_update_runtime.py:23/25 — 死字段 resolve_group/assert_group 及 sub2_upload_override.py 构造点传参删除。
3. sub2_runtime.py:952 — 死函数 `_export_safe_int` 删除。
4. sms_cost_history.py — `_directory_signature` 四处全写无读;删除字段写入与 `_dir_signature` 调用点(保留方法若测试引用)。
5. sms_key_pool.py:11 — 死 `import re` 删除。
6. mailbox_sub2_results.py vs mailbox_result_index.py:53 — `latest_sub2_accounts_by_email` 双实现收敛:index `_build_indexes` 改调 results 版纯函数(或共享 fold),平局语义以现运行时(index 版)为准,回归 mailbox_admin 定向测试。
7. mailbox_admin.py:316-413 — reveal 三方法 30 行重复前奏抽 `_reveal_row(row_id, line_no)`。

## 暂不执行(需用户决策/高风险,仅登记)
- free_protocol_flow.py prelude 路径跳过邮箱租约确认(业务语义决策:prelude 命中即 confirm 还是强制走 confirm,涉及 3.4/3.5 边界)。
- free_register_runtime.py legacy FreeProxyPool 兼容层(历史 roxybrowser 路径,AGENTS 3.1 已声明只读)。
- runtime_* 之外的邮箱超大文件拆分(mailbox_otp_service/mailbox_admin/sms_web 拆段)——体量大,另行排期。
- mfa_retry/网络错误分类三套/HTTP 状态提取 7 处等大面收敛——另行排期。
