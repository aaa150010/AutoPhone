# AGENTS.md

## Repository Overview

GPT 注册中心 (gptPhone) is a macOS-local Flask application with a Vue 3 and Element Plus dashboard. It has two isolated workspaces: the recovered SMS/OAuth registration workflow and a maintained Free registration workflow with protocol and RoxyBrowser drivers. The runnable recovered backend is Python 3.13 bytecode, so maintainable backend changes live in runtime overrides instead of reconstructed source.

## Editable Boundaries

- Put backend behavior changes in `mac_overrides/`. `mac_overrides/web_gui.py` loads the recovered modules and applies focused monkeypatches.
- Put reusable backend logic that can be tested without the recovered runtime in separate modules such as `mac_overrides/sms_runtime.py` and `mac_overrides/task_progress.py`.
- Keep Free configuration, mailbox/proxy pools, tasks, logs, locks and results under `${GPTPHONE_DATA_DIR}/free_register/`; ordinary SMS/OAuth routes must not aggregate, mutate or consume that state.
- Route ordinary and Free URL-based email verification through `mac_overrides/mailbox_otp_service.py`. Keep source parsing, baselines, old-code exclusion and diagnostics shared while preserving each workflow's independent network configuration.
- Keep payment-link extraction under `mac_overrides/payment_tools.py` and `mac_overrides/payment_protocol/`; its data root is `${GPTPHONE_DATA_DIR}/payment_tools/` and it must never reuse ordinary task state. Third-party modes require an explicit per-batch domain confirmation, and result links are reveal-on-demand only.
- Keep proxy/network diagnostics under `mac_overrides/network_tools.py`, `mac_overrides/network_mihomo.py` and `mac_overrides/network_tools_routes.py`; its data root is `${GPTPHONE_DATA_DIR}/network_tools/`. A test must use the selected proxy's declared protocol, never inherit environment proxies, switch nodes, or silently fall back to Clash.
- Put dashboard source changes in `frontend/src/`. Extract a component when a control group, card, table, operation bar, or behavior has its own responsibility.
- Treat `business_pyc/` and `plus_launcher.pyc` as runtime artifacts, not editable source.
- Treat `pycdc_attempt/` as hints only. It is incomplete and must not be used as runnable source. Use `disassembly/` to inspect recovered behavior and verify assumptions against live method signatures.

## Maintainability Limits

- New Python modules should target at most 800 lines and must not exceed 1,200 lines. New Vue single-file components should target at most 500 lines and must not exceed 700 lines.
- A file already above its hard limit must not grow. Every change that touches it must extract at least one complete responsibility and leave the file with a net line-count reduction.
- Extract cohesive provider/key policy, selection/ranking, wait orchestration, cleanup/cost, configuration, lifecycle, and public-state responsibilities instead of accumulating unrelated helpers in an entry module.
- Preserve compatibility exports and original callable signatures while moving code. Treat mechanical extraction and behavior changes as separate stages, and run the full relevant test set after each stage.
- Performance optimizations require a defaulted rollback switch, credential-redacted metrics, and explicit rollback conditions. Throughput must not trade away success rate, diagnostics, credential safety, cancellation behavior, or cleanup semantics.
- For the current SMS optimization baseline, evaluate a rolling 100-task window and disable the SMS optimization if success falls more than 2 percentage points below 83.9%, two confirmed late codes are lost after early release, cancellation or duplicate-order counts rise, or cost per successful account increases by more than 10%. Protocol pressure, HTTP 429, or session invalidation must immediately return adaptive task admission to its configured baseline.
- For recovered behavior, query `disassembly/index.json` first and read only the matching slices. Do not load an entire generated disassembly when an indexed symbol slice is available. Confirm callable signatures with Python 3.13 `inspect.signature`.

## Runtime Override Rules

- Capture original methods before patching and keep patches narrowly scoped.
- Match the original callable signature, including keyword-only arguments. Verify uncertain signatures with `inspect.signature` in the Python 3.13 virtual environment.
- Avoid changing unrelated recovered behavior while adding an override.
- Never log or expose raw SMS, SUB2, Pixel, OAuth, mailbox, or proxy credentials. Public state uses masks or SHA-256 short fingerprints.
- Preserve existing configuration fields and their established page order unless the user explicitly requests a removal or reorder.
- `auth_session_retries` is a UI count of additional retries: `0` means no retry after the first attempt.
- Keep task progress events free of credentials and user data. Repeated events in the same stage must not reset elapsed time, and terminal tasks must freeze their last valid stage.

## Local Network Environment

- On the user's current Mac, Clash Verge exposes the configured HTTP proxy at `http://127.0.0.1:7897`. Treat this as the authoritative host proxy for OpenAI Auth, Sentinel, Node/Sentinel, and other traffic that uses the main proxy setting.
- Free mailbox retrieval defaults to its own explicit `http://127.0.0.1:7897` setting and must never reuse the account's residential registration proxy. Direct mode and local-proxy mode both disable inherited `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` values.
- `http://127.0.0.1:12334` is not a configured or valid current proxy port. If it appears in a new task's effective proxy label, error detail, subprocess arguments, or environment, treat it as a defect caused by stale process state, an inherited proxy environment variable, or an unintended configuration override and trace it to the source.
- Network diagnostics must record the effective proxy label or redacted fingerprint at the Node bridge boundary. Do not infer the effective host proxy from a sandbox-only localhost probe: the sandbox may deny or isolate loopback access. Use a host-level/approved real-network check when verifying Clash Verge connectivity.
- High-concurrency tests must compare the configured `7897` proxy path at concurrency 1, 4, and 8, and must distinguish proxy connection failures from Sentinel or Node resource failures. Never silently fall back to `12334`.

## Diagnostic Error Contract

- Every pipeline failure shown in task results, mailbox rows, upload records, or logs must include a stable node code, a Chinese node label, and a credential-redacted actionable cause. The persisted result and public API should carry the same structured failure identity.
- Cover OAuth session creation, Node/Sentinel initialization, OpenAI authorization, mailbox login and verification, phone acquisition and submission, SMS wait and verification, profile completion, OAuth callback, token exchange, SUB2 upload and test, Pixel enqueue/import/share/verification, persistence, and notification nodes explicitly.
- Preserve safe HTTP status and provider error codes when available. Never publish raw response bodies, OAuth URLs with query parameters, cookies, phone numbers, SMS or email codes, passwords, TOTP secrets, SMS keys, access/refresh/ID/admin tokens, authorization headers, proxy credentials, or mailbox credentials.
- Do not replace a known node failure with generic text such as `操作失败`, `failed`, or `授权或上传未完成`. If no provider detail exists, retain the exact node and state that no detail was returned, for example `OAuth Token 交换失败：服务端未返回错误详情`.
- Terminal classifiers such as `account_banned` must retain their stable public message while storing only a redacted technical detail locally. Cleanup, cancellation, upload, or notification failures must not overwrite the original terminal cause.
- Async Pixel failures must not change registration success. Persist the target, exact stage, attempt count, retryability, and sanitized cause in the outbox so retries and post-restart diagnosis keep their context.
- Add fake-provider tests for every new failure branch and assert node attribution, diagnostic specificity, persistence across retry/restart where relevant, and credential redaction.

## Frontend Conventions

- This application is desktop-only. Design and verify for desktop viewports; do not add mobile, narrow-screen, or responsive adaptations unless the user explicitly requests them.
- Use Vue 3 single-file components and Element Plus controls. Prefer `size="small"` through the global provider.
- Use Element Plus native `show-password`; do not build custom password-eye overlays.
- Use icons from `@element-plus/icons-vue` for familiar actions and add tooltips to icon-only buttons.
- Keep the sidebar compact, `el-main` padding at `5px`, and page height constrained to the viewport. Configuration, task results, logs, and tables should scroll inside their own allocated regions.
- Keep `RunOperationBar` as two rows of three equal-width buttons in its established order. Keep other action groups on one line when requested.
- Reuse `DashboardMetricCard` for dashboard summary cards. The icon belongs on the left, with title over value on the right.
- Keep numeric card transitions centralized in `RollingMetricValue`. Animate only actual numeric changes and honor `prefers-reduced-motion`.
- Reuse `ContentEmptyState` for empty tables and logs. Hide controls that have no useful action while their content area is empty.
- Keep Element Plus locale Chinese and verify pagination labels remain Chinese.
- Keep global scrollbars thin and blue, including native overflow containers and Element Plus scrollbars.
- Mailbox table selection must use a stable row key. Clear selection before and after destructive mutations so line renumbering cannot select another row.
- Mailbox status means current pool state, not historical task success. While a matching task has unfinished progress, show the pool row as running and refresh its concrete progress stage in real time.
- Reuse `TaskProgressCell` for task and mailbox progress. Run one shared one-second clock per visible table only while that table contains active progress.

## Generated And Local Files

- `frontend/dist/` is tracked. Rebuild it after every frontend source change and commit the updated hashed assets with `frontend/dist/index.html`.
- Never commit `data/`, `mac_runtime/`, `engine/`, `node_chain.dat`, `frontend/node_modules/`, caches, local exports, or secrets.
- Do not delete the retained reference copies under `/Users/lwh/projects/AutoRegister`, `/private/tmp/codex-auto-register-check.d2Qxkf/repo` or `/private/tmp/grok-gpt-check.XYMs6P/repo` unless the user explicitly requests it.
- Do not delete or overwrite user runtime data while testing. Use a temporary data directory for Flask integration checks.

## Free/Roxy Reference Implementations

Free 双链路和 RoxyBrowser 行为变更前，必须先对照以下两个成熟项目的对应实现：

- 同级项目 `/Users/lwh/projects/AutoRegister`：重点参考 `core/roxy_registration.py`、`core/roxybrowser_client.py`、`core/otp_utils.py`、`core/humanize.py`、`core/live_check_service.py`、`config/proxy.py` 和 `config/roxybrowser.py`。
- 开源项目 `https://github.com/maile456/codex-auto-register`：当前临时副本为 `/private/tmp/codex-auto-register-check.d2Qxkf`，重点参考 `backend/run_manager.py`、`backend/probe_store.py`、`backend/roxy_client.py`、`backend/mailbox_client.py`、`backend/browser_worker.py` 和 `backend/run_log_store.py`。

只吸收页面状态机、邮箱 OTP 轮询、代理租约、并发槽位、Roxy `connection_info` 对账、失败清理和结构化日志思路；不得复制参考项目的密钥、账号、运行数据、Cookie、Token 或第三方授权信息。当前 Free 数据隔离和普通接码流程优先于参考项目，参考实现不能改变普通接码链路。参考副本不纳入 Git，也不读取其中的敏感数据；本轮按用户要求保留副本。

## Release Notes

- Keep all user-visible release copy in `frontend/src/releaseNotes.ts`; UI components may render that data but must not embed release-specific feature descriptions.
- Any agent completing user-visible code changes must, without waiting for another user reminder, review the current code diff, add concise Chinese feature points and usage instructions to the current release record, and increment both `currentRelease.version` and `frontend/package.json` to the same version before delivery.
- The first app launch after a version change must show the release-notes dialog for every local user, including developers. Acknowledgement may persist only the non-sensitive release version in `localStorage`; never persist mailbox, proxy, SMS, OAuth, SUB2, Pixel, or other credential data there.
- Before final verification, compare the release-note sections against the complete user-visible diff so newly added, changed, or removed workflows are not omitted.

## Verification

Run backend tests and syntax checks from the repository root:

```sh
mac_runtime/.venv/bin/python -m unittest discover -s tests -v
mac_runtime/.venv/bin/python -m py_compile \
  mac_overrides/error_observability.py \
  mac_overrides/web_gui.py \
  mac_overrides/sms_runtime.py \
  mac_overrides/task_progress.py \
  tests/test_error_observability.py \
  tests/test_sms_runtime.py \
  tests/test_task_progress.py
```

Run frontend checks and rebuild production assets:

```sh
cd frontend
npx vue-tsc --noEmit
npm run build
```

Then run `git diff --check`. Do not start or restart the local Flask service for verification unless the user explicitly asks. Do not use the in-app browser, browser skills, Chrome, Playwright, or computer-use for frontend verification; the user performs manual visual verification. Automated frontend verification is limited to type checks, builds, and tests. Routine frontend verification targets desktop viewports only; do not perform mobile or narrow-screen adaptation unless the user explicitly requests it. Never click real preflight, registration, SMS, SUB2, Pixel, payment extraction or proxy-test actions during verification.
