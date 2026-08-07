# Token Tool Online Mailboxes

This service adds a password-protected mailbox registry to the existing static
Token Tool deployment. It runs as a separate container on the existing
`note_default` Docker network and stores SQLite data under
`/opt/token-tool-mailboxes-data`.

Deployment order:

1. Copy this directory to `/opt/token-tool-mailboxes`.
2. Run `python3 provision.py` once. It writes `.env` and a root-only
   `credentials.once.json` without printing secrets.
3. Run `docker compose -f compose.yml up -d --build`.
4. Add `Caddyfile.snippet` before the existing `/token-tool/*` handler, validate,
   and reload Caddy.
5. Run `python3 patch_token_tool_home.py` to add the management-page link.

Never commit `.env`, `credentials.once.json`, the SQLite database, or copied
credential handoff files.
