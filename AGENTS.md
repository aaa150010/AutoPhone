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
- Never log or expose raw SMS, SUB2, nvtoken, OAuth, mailbox, or proxy credentials. Public state uses masks or SHA-256 short fingerprints.
- Keep network and paid-service tests behind fake providers. Do not call real SMS preflight or start a real run during automated verification.
- Preserve existing configuration fields and their established page order unless the user explicitly requests a removal or reorder.
- `auth_session_retries` is a UI count of additional retries: `0` means no retry after the first attempt.
- Keep task progress events free of credentials and user data. Repeated events in the same stage must not reset elapsed time, and terminal tasks must freeze their last valid stage.

## Frontend Conventions

- Use Vue 3 single-file components and Element Plus controls. Prefer `size="small"` through the global provider.
- Use Element Plus native `show-password`; do not build custom password-eye overlays.
- Use icons from `@element-plus/icons-vue` for familiar actions and add tooltips to icon-only buttons.
- Keep the sidebar compact, `el-main` padding at `5px`, and page height constrained to the viewport. Configuration, task results, logs, and tables should scroll inside their own allocated regions.
- Keep action groups on one line when requested; permit horizontal scrolling only on the action group when the viewport is too narrow.
- Reuse `DashboardMetricCard` for dashboard summary cards. The icon belongs on the left, with title over value on the right.
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
  mac_overrides/web_gui.py \
  mac_overrides/sms_runtime.py \
  mac_overrides/task_progress.py \
  tests/test_sms_runtime.py \
  tests/test_task_progress.py
```

Run frontend checks and rebuild production assets:

```sh
cd frontend
npx vue-tsc --noEmit
npm run build
```

Then run `git diff --check`. For UI work, start the Flask app on `127.0.0.1:18777` and verify both `/` and `/mailboxes` at desktop and narrow widths. Do not click real preflight or start controls during visual QA.
