# AGENTS.md

## Repository Overview

gptPhone is a macOS-local Flask application with a Vue 3 and Element Plus dashboard. The runnable business backend was recovered as Python 3.13 bytecode. Most maintainable backend changes therefore live in runtime overrides instead of reconstructed source.

## Editable Boundaries

- Put backend behavior changes in `mac_overrides/`. `mac_overrides/web_gui.py` loads the recovered modules and applies focused monkeypatches.
- Put reusable backend logic that can be tested without the recovered runtime in separate modules such as `mac_overrides/sms_runtime.py` and `mac_overrides/task_progress.py`.
- Put dashboard source changes in `frontend/src/`. Extract a component when a control group, card, table, operation bar, or behavior has its own responsibility.
- Treat `business_pyc/` and `plus_launcher.pyc` as runtime artifacts, not editable source.
- Treat `pycdc_attempt/` as hints only. It is incomplete and must not be used as runnable source. Use `disassembly/` to inspect recovered behavior and verify assumptions against live method signatures.

## Runtime Override Rules

- Capture original methods before patching and keep patches narrowly scoped.
- Match the original callable signature, including keyword-only arguments. Verify uncertain signatures with `inspect.signature` in the Python 3.13 virtual environment.
- Avoid changing unrelated recovered behavior while adding an override.
- Never log or expose raw SMS, SUB2, Pixel, OAuth, mailbox, or proxy credentials. Public state uses masks or SHA-256 short fingerprints.
- Preserve existing configuration fields and their established page order unless the user explicitly requests a removal or reorder.
- `auth_session_retries` is a UI count of additional retries: `0` means no retry after the first attempt.
- Keep task progress events free of credentials and user data. Repeated events in the same stage must not reset elapsed time, and terminal tasks must freeze their last valid stage.

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
- Do not delete or overwrite user runtime data while testing. Use a temporary data directory for Flask integration checks.

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

Then run `git diff --check`. Do not start or restart the local Flask service for verification unless the user explicitly asks. Do not use the in-app browser, browser skills, Chrome, Playwright, or computer-use for frontend verification; the user performs manual visual verification. Automated frontend verification is limited to type checks, builds, and tests. Routine frontend verification targets desktop viewports only; do not perform mobile or narrow-screen adaptation unless the user explicitly requests it. Never click real preflight, registration, SMS, SUB2, or Pixel actions during verification.
