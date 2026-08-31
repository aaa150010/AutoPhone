# Selected Business Bytecode

The current macOS dashboard is branded as **GPT 注册中心** and exposes two isolated workspaces: the recovered SMS/OAuth workflow and the maintained Free registration workflow. Recovered bytecode remains read-only; maintained behavior is implemented in `mac_overrides/`.

These files were selected from the PyInstaller/PYZ extraction as likely first-party modules.

- `plus_launcher.pyc`
- `pyiboot01_bootstrap.pyc`
- `pyi_rth_inspect.pyc`
- `pyi_rth_pkgutil.pyc`
- `pyi_rth_multiprocessing.pyc`
- `pyi_rth_cryptography_openssl.pyc`
- `pyi_rth_setuptools.pyc`
- `chatgpt_fields.pyc`
- `codex_chain_runner.pyc`
- `codex_node_bridge.pyc`
- `codex_oauth_chain.pyc`
- `codex_runtime_context.pyc`
- `email_code_poll.pyc`
- `email_provider_branch.pyc`
- `file_safety.pyc`
- `imap_poller.pyc`
- `license_gate.pyc`
- `mailmanage_client.pyc`
- `oauth_local_archive.pyc`
- `openai_oauth.pyc`
- `proxy_scope.pyc`
- `resource_runtime.pyc`
- `runtime.pyc`
- `runtime_paths.pyc`
- `sms_providers.pyc`
- `sms_selector.pyc`
- `sub2_groups.pyc`
- `sub2_session.pyc`
- `upload_targets.pyc`
- `web_gui.pyc`
- `tools/__init__.pyc`
- `tools/high_pressure_test.pyc`
- `tools/self_mailbox_pool/__init__.pyc`
- `tools/self_mailbox_pool/mailbox_pool.pyc`

## Maintained Runtime Overrides

- `mac_overrides/free_register/`: Free task contracts, revisioned repository,
  mailbox leases, scheduler, retry policy, worker timing and composition root.
- `mac_overrides/free_register_runtime.py`: Free controller compatibility facade
  and recovered-call-signature assembly. New task, lease, retry or timing policy
  belongs in `free_register/`, not in this facade.
- `mac_overrides/free_protocol_runtime.py`: isolated Free full-protocol driver.
- `mac_overrides/free_camoufox/`: typed flow contracts, page transport,
  transition validation, browser-pool boundary, debug artifact sanitization and
  runner composition for the Camoufox chain.
- `mac_overrides/free_camoufox_runtime.py`: recovered Camoufox compatibility
  facade. New page behavior must enter through the package transport/state
  boundaries instead of adding another private flow here.
- `mac_overrides/free_storage.py`: Free-only SQLite transaction boundary for
  mailboxes, shared healthy proxies, tasks, results, revisions and leases.
- `mac_overrides/free_storage_adapters.py`: compatibility adapters that project
  the SQLite repositories through the historical pool/task APIs.
- `mac_overrides/free_rebind_storage.py`: independent SQLite repository for
  protocol-only account rebind jobs; it never shares task tables with Free
  registration.
- `mac_overrides/free_register_config.py`: `${GPTPHONE_DATA_DIR}/free_register/` configuration, defaults, masking and migration.
- `mac_overrides/free_proxy_runtime.py`: structured Free proxy pool using one shared `healthy_random` allocator, leases, health and quarantine; legacy country/group fields are migration-only and never a selection strategy.
- `mac_overrides/free_live_check.py`: fast and deep account liveness checks using the account's saved registration proxy.
- `mac_overrides/diagnostic_writer.py`: the single structured-event adapter;
  binds task/batch/driver context, applies field allowlists and subject HMAC
  masking, and keeps diagnostic outages best-effort.
- `mac_overrides/free_log_migration.py`: one-shot, idempotent cleanup for
  obsolete Free `logs.json` and `task_logs/*.json`; completion is marked in the
  Free-owned `free_register.sqlite3` `storage_meta` table.
- `mac_overrides/mailbox_otp_service.py`: shared mailbox OTP source registry, network transport, baseline/old-code exclusion, polling and credential-safe diagnostics.
- `mac_overrides/mailbox_code_parser.py`: shared HTML/JSON/Base64/Japanese OTP field normalization and context-aware six-digit extraction.
- `mac_overrides/mailbox_pickup_runtime.py`: `/pickup` and `/latest` JavaScript shell discovery, same-origin `/api/messages` and detail endpoint construction.
- `mac_overrides/mailbox_request_runtime.py`: request baseline, old-code exclusion, bounded fallback polling and mailbox diagnostics state.
- `mac_overrides/free_mailbox_otp.py`: Free compatibility wrapper; mailbox retrieval uses Free's explicit local-proxy/direct policy and never the registration residential proxy.

### Free diagnostic data flow

New runtime events flow through `DiagnosticEventWriter` into the append-only
`DiagnosticStore` (`diagnostics.sqlite3`). `FreeLogStore` remains an API
compatibility facade. New runtime assembly should set `legacy_projection=False`;
compatibility rows are then projected from the structured event chain and no
JSON logs are created. Legacy JSON files are not migrated and can be removed
once with:

```sh
mac_runtime/.venv/bin/python -m mac_overrides.free_log_migration \
  --data-dir "$GPTPHONE_DATA_DIR/free_register"
```

The command targets only the exact legacy files and records completion in
`storage_meta`; mailbox, proxy, task, account-result and diagnostic data are
outside its deletion scope.

### Free persistence boundaries

```text
${GPTPHONE_DATA_DIR}/free_register/free_register.sqlite3
  mailboxes + healthy_random proxies + registration tasks/results + storage_meta

${GPTPHONE_DATA_DIR}/free_register/rebind/free_rebind.sqlite3
  protocol-only rebind jobs/results + rebind migration metadata

${GPTPHONE_DATA_DIR}/diagnostics/diagnostics.sqlite3
  redacted append-only incidents/events and integrity metadata only
```

Registration and rebind credentials stay in their owning repository's private
payload columns and are returned only by explicit secret endpoints. The
diagnostic database stores only allowlisted redacted fields and HMAC
fingerprints; it is not a bridge for sharing mailbox, proxy, task or account
state. Legacy JSON/TXT task, pool and result data is imported once under a
`storage_meta` marker and is no longer the runtime write path.

## 独立工具模块

- `mac_overrides/payment_tools.py`: 独立支付提链任务、并发、取消、重试、第三方确认、结果按需读取和敏感值隔离。
- `mac_overrides/payment_protocol/`: 本地支付协议提炼适配器，保留 MIT 来源许可证；只生成/提炼链接，不执行扣款。
- `mac_overrides/payment_pay153_browser.py`: 可选的 pay.153.ink Selenium 适配器，默认无头，缺少 Selenium 时只返回结构化配置错误。
- `mac_overrides/payment_tools_routes.py`: 支付工具 API 装配，不读取普通接码任务状态。
- `mac_overrides/network_tools.py`: 独立代理记录、国家/分组、协议解析、快速/深度测活和出口 IP 结果。
- `mac_overrides/network_mihomo.py`: Mihomo 隔离临时进程生命周期；不修改 Clash Verge 当前配置或系统代理。
- `mac_overrides/network_tools_routes.py`: 代理导入、订阅解析、分组和固定代理测活 API。

支付工具和网络工具的运行数据分别位于 `payment_tools/` 与 `network_tools/`，不会写入 Free 注册、普通接码或共享运行状态。支付第三方模式和任何真实节点测试都必须由用户在界面中明确发起；测试夹具只使用假服务、假代理和假响应。

The default Free mailbox transport is `http://127.0.0.1:7897`. Ordinary SMS/OAuth registration and Free registration share the OTP engine but keep independent network settings and data stores.
