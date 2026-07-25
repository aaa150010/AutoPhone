# PlusBindTool Recovery Notes

Input package:

- `/Users/lwh/Downloads/PlusBindTool_V1.0.3_build47_win/PlusBindTool_V1.0.3.exe`
- PyInstaller archive, Python 3.13 bytecode
- PyInstaller archive is not encrypted
- Entry point: `plus_launcher.pyc`

Generated contents:

- `raw_extracted/`: full PyInstaller extraction, including `PYZ.pyz_extracted/`
- `business_pyc/`: selected first-party-looking `.pyc` modules
- `disassembly/`: reliable `pydisasm` bytecode output for selected modules
- `pycdc_attempt/`: best-effort `pycdc` decompiler output
- `external_assets/node_chain.dat`: external data file from the original package
- `BUSINESS_MODULES.md`: selected module list
- `tools/recover.py`: reproducible recovery script used to generate the artifacts
- `启动_gptPhone.command`: mac double-click launcher for the recovered WebUI
- `mac_runtime/.venv`: mac Python 3.13 virtual environment with native dependencies
- `plus_launcher.pyc`: root launcher copy used by the mac command
- `data/`: runtime data directory used by the mac command

Important limitation:

The bundled bytecode is Python 3.13. Current local decompilers tested here (`decompyle3`,
`uncompyle6`, and latest `pycdc`) do not fully decompile Python 3.13 bytecode into runnable
Python source. `pycdc_attempt/` is therefore incomplete and should be treated only as a hint.
The most complete readable output is in `disassembly/`.

Notable recovered modules:

- `plus_launcher`
- `web_gui`
- `runtime`
- `codex_chain_runner`
- `codex_node_bridge`
- `codex_oauth_chain`
- `license_gate`
- `sms_providers`
- `sms_selector`
- `imap_poller`
- `mailmanage_client`
- `openai_oauth`
- `sub2_session`
- `tools/high_pressure_test`
- `tools/self_mailbox_pool/mailbox_pool`

External data:

`node_chain.dat` begins with the magic bytes `NCR1`, followed by high-entropy data. It is not
plain JavaScript, zip, asar, or a directly readable Node bundle from the quick inspection done
here.

Mac launcher:

Double-click `启动_gptPhone.command` to start the WebUI. It uses port `18777` by default and
prints the URL in the Terminal window. To use a different port from Terminal:

```sh
GPTPHONE_PORT=18788 /Users/lwh/Downloads/gptPhone/启动_gptPhone.command
```

Verified locally:

- Python 3.13 can run the recovered entry bytecode
- mac-native dependencies are installed in `mac_runtime/.venv`
- WebUI starts and `/api/state` returns JSON
- Runtime data resolves to `/Users/lwh/Downloads/gptPhone/data`
- Manual email verification UI is removed in the mac override layer
- Manual email verification backend entry points return disabled
- The WebUI is overridden to a light color theme
- GPTMail-specific fields are hidden until `GPTMail 收码` is checked
- SUB2 defaults are hardwired and read-only in the UI
- SMS API key is hardwired and read-only in the UI
- Proxy defaults to `http://127.0.0.1:7897` and remains editable
- SMS max price defaults to `0.08` and remains editable

Configured defaults:

- SUB2 URL: `http://39.106.173.33:8080/`
- SUB2 account: `admin@sub2api.local`
- SUB2 group: `自动化接码分组`
- OpenAI proxy default: `http://127.0.0.1:7897`
- SMS max price default: `0.08`

SUB2 connectivity check:

- Base URL returned HTTP 200
- Login returned success
- Group `自动化接码分组` was found with id `5` and status `active`

Known mac limitation:

The original Windows release includes a Windows `node.exe` and an external encrypted/custom
`node_chain.dat`. The mac launcher uses the local `node` binary when available, but the real
Sentinel runner from `node_chain.dat` was not converted into a mac Node runner in this pass.
