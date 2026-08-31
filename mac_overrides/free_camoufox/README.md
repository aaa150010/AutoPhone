# Free Camoufox boundaries

This package is the migration boundary for the Free Camoufox chain.  The
historical [`free_camoufox_runtime.py`](../free_camoufox_runtime.py) remains
the compatibility implementation while callers move to the smaller services.

| Module | Responsibility | Must not contain |
| --- | --- | --- |
| `contracts.py` | Typed, in-memory request/result/state contracts | Browser imports, persistence, secrets |
| `errors.py` | Transport error classification and recovery metadata | Page interaction or retry loops |
| `transport.py` | Duck-typed page operations (`visible`, `fill`, `click`, `goto`, `evaluate`) | Business state decisions, retries |
| `state_machine.py` | Validated page-state transitions, polling coordinator and history | Locator calls or mailbox access |
| `browser_pool.py` | Pool lifecycle gateway and compatibility exports | OTP/provider semantics |
| `debug_artifacts.py` | Bounded trace/artifact capture and redaction | Raw page values, credentials, tokens |
| `runner.py` | Runner composition boundary and typed-request adapter | A second registration flow |

## Migration rule

New code should depend on these boundaries rather than importing private
helpers from the legacy runtime.  The legacy lazy exports exist only to keep
old manager/tests working during migration.  Any eventual implementation move
must preserve the existing runner signature and the shared
`mailbox_otp_service.py` strategy; it must not add another mailbox provider or
browser state machine.
