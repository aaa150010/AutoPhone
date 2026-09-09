// Minimal resident worker stub for pool contract tests. Mirrors the real
// sentinel_worker.js protocol without loading the Sentinel SDK.
'use strict';

const readline = require('readline');

function writeLine(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const text = String(line || '').trim();
  if (!text) return;
  let message;
  try {
    message = JSON.parse(text);
  } catch (err) {
    writeLine({ ok: false, error: `invalid json: ${err.message}` });
    return;
  }
  const id = message && message.id;
  if (message.type === 'ping') {
    writeLine({ id, ok: true, pong: true, worker_ready: true });
    return;
  }
  const payload = (message && message.payload) || {};
  if (payload.crash) {
    process.exit(1);
  }
  const sleepMs = Number(payload.sleep_ms || 0);
  setTimeout(() => {
    writeLine({
      id,
      ok: true,
      mode: 'real',
      version: 'stub-worker-v1',
      flow: String(payload.flow || ''),
      pid: process.pid,
      request_id: id,
      worker_ready: true,
      token_generated: false,
    });
  }, sleepMs);
});

rl.on('close', () => process.exit(0));
