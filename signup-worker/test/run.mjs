/**
 * Integration test for the sign-up Worker. Runs in plain Node, no npm install
 * needed: the worker-mailer import is swapped for a stub, and global fetch
 * intercepts the DNS resolver and the Infomaniak API.
 *
 *   node test/run.mjs
 */
import { readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const STUB = `globalThis.__mails = [];
class WorkerMailer {
  static async connect(o) { return new WorkerMailer(o); }
  async send(msg) { globalThis.__mails.push(msg); }
  async close() {}
}`;

const source = await readFile(new URL('../src/index.js', import.meta.url), 'utf8');
const patched = source.replace(/^import \{ WorkerMailer \} from 'worker-mailer';$/m, STUB);
if (patched === source) throw new Error('could not stub the worker-mailer import');
const tmp = join(tmpdir(), `sigwus-worker-${process.pid}.mjs`);
await writeFile(tmp, patched);
const worker = (await import(pathToFileURL(tmp).href)).default;


const BASE_ENV = {
  IK_TOKEN: 'test-token',
  IK_DOMAIN_ID: '64876',
  HMAC_SECRET: 'unit-test-secret-unit-test-secret',
  SITE_URL: 'https://sig-wus.org',
  ALLOWED_ORIGINS: 'https://sig-wus.org,https://sig-wus.github.io',
  PUBLIC_URL: 'https://worker.example.workers.dev',
  SMTP_HOST: 'mail.infomaniak.com',
  SMTP_PORT: '587',
  SMTP_USER: 'contact@sig-wus.org',
  SMTP_PASS: 'x',
  FROM_EMAIL: 'contact@sig-wus.org',
  FROM_NAME: 'SIG-WUS',
  NOTIFY_EMAIL: '',
  OPT_IN_MODE: 'single',
  WELCOME_MAIL: '0',
};

let apiCalls = [];
let mxAnswer = true;

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  if (u.includes('cloudflare-dns.com')) {
    return new Response(JSON.stringify(mxAnswer ? { Answer: [{ type: 15 }] } : { Answer: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  }
  if (u.includes('api.infomaniak.com')) {
    apiCalls.push({ url: u, body: JSON.parse(init.body), auth: init.headers.Authorization });
    return new Response(JSON.stringify({ result: 'success', data: { id: 1, status: 'active' } }), { status: 201 });
  }
  throw new Error('unexpected fetch: ' + u);
};

const GOOD = {
  email: 'Ada@Example.ORG', firstname: 'Ada', lastname: 'Lovelace',
  affiliation: 'ETH Zurich', country: 'Switzerland',
  groups: ['STANDARDS', 'PLATFORM'], consent: true, website: '',
};

function post(body, env = {}, origin = 'https://sig-wus.org') {
  return worker.fetch(
    new Request('https://worker.example.workers.dev/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin, 'CF-Connecting-IP': '203.0.113.9' },
      body: JSON.stringify(body),
    }),
    { ...BASE_ENV, ...env }
  );
}

const results = [];
const check = (name, cond, detail = '') => results.push({ name, pass: !!cond, detail });

/* 1. happy path, single opt-in ------------------------------------------- */
apiCalls = [];
let res = await post(GOOD);
let json = await res.json();
const call = apiCalls[0];
check('single: 200 + message', res.status === 200 && /on the list/i.test(json.message), json.message);
check('single: writes to Infomaniak once', apiCalls.length === 1);
check('single: email normalised to lowercase', call && call.body.email === 'ada@example.org', call && call.body.email);
check('single: base group only + areas written to sig-area',
  JSON.stringify(call.body.groups) === JSON.stringify(['sig-wus community']) &&
  call.body.fields['sig-area'] === 'Standards & Regulatory; Open Exchange Platform',
  JSON.stringify({ groups: call.body.groups, 'sig-area': call.body.fields['sig-area'] }));
check('single: consent evidence stored',
  /^\d{4}-/.test(call.body.fields['consent-at']) && /single opt-in/.test(call.body.fields['consent-source']) &&
  /203\.0\.113\.9/.test(call.body.fields['consent-source']), JSON.stringify(call.body.fields));
check('single: token sent as bearer', call.auth === 'Bearer test-token');

/* 2. honeypot ------------------------------------------------------------- */
apiCalls = [];
res = await post({ ...GOOD, website: 'http://spam.example' });
check('honeypot: fake success, nothing written', res.status === 200 && apiCalls.length === 0);

/* 3. validation ----------------------------------------------------------- */
apiCalls = [];
res = await post({ ...GOOD, email: 'not-an-email' });
check('validation: bad email rejected', res.status === 400 && apiCalls.length === 0);
res = await post({ ...GOOD, consent: false });
check('validation: missing consent rejected', res.status === 400);
res = await post({ ...GOOD, firstname: '' });
check('validation: missing name rejected', res.status === 400);

/* 4. group injection ------------------------------------------------------ */
apiCalls = [];
await post({ ...GOOD, groups: ['EVENTS', 'EVIL', 'admin'] });
check('areas: unknown values dropped',
  JSON.stringify(apiCalls[0].body.groups) === JSON.stringify(['sig-wus community']) &&
  apiCalls[0].body.fields['sig-area'] === 'Events & Education',
  JSON.stringify({ groups: apiCalls[0].body.groups, 'sig-area': apiCalls[0].body.fields['sig-area'] }));

/* 5. MX pre-check --------------------------------------------------------- */
apiCalls = [];
mxAnswer = false;
res = await post({ ...GOOD, email: 'ada@gmial-typo-domain.invalid' });
check('mx: undeliverable domain rejected', res.status === 400 && apiCalls.length === 0);
mxAnswer = true;

/* 6. CORS ----------------------------------------------------------------- */
res = await post(GOOD, {}, 'https://evil.example');
check('cors: foreign origin blocked', res.status === 403);
res = await worker.fetch(new Request('https://w/subscribe', {
  method: 'OPTIONS', headers: { Origin: 'https://sig-wus.org' } }), BASE_ENV);
check('cors: preflight echoes allowed origin',
  res.status === 204 && res.headers.get('Access-Control-Allow-Origin') === 'https://sig-wus.org');

/* 7. double opt-in -------------------------------------------------------- */
apiCalls = []; globalThis.__mails.length = 0;
res = await post(GOOD, { OPT_IN_MODE: 'double' });
json = await res.json();
const mail = globalThis.__mails[0];
const link = (mail.text.match(/https:\/\/\S+/) || [])[0];
check('double: nothing written before confirmation', res.status === 200 && apiCalls.length === 0);
check('double: confirmation mail sent with link', !!link, link);

res = await worker.fetch(new Request(link), { ...BASE_ENV, OPT_IN_MODE: 'double' });
check('double: valid link writes subscriber + redirects',
  res.status === 302 && apiCalls.length === 1 &&
  res.headers.get('Location') === 'https://sig-wus.org/?subscribed=1', res.status);
check('double: consent_source records double opt-in',
  /double opt-in/.test(apiCalls[0].body.fields['consent-source']));

apiCalls = [];
res = await worker.fetch(new Request(link.replace(/.$/, 'X')), { ...BASE_ENV, OPT_IN_MODE: 'double' });
check('double: tampered signature rejected', res.status === 400 && apiCalls.length === 0);

const realNow = Date.now;
Date.now = () => realNow() + 49 * 3600 * 1000;
res = await worker.fetch(new Request(link), { ...BASE_ENV, OPT_IN_MODE: 'double' });
Date.now = realNow;
check('double: link expires after 48 h', res.status === 410);

/* 8. misc ----------------------------------------------------------------- */
res = await worker.fetch(new Request('https://w/health'), BASE_ENV);
check('health endpoint', res.status === 200);
res = await worker.fetch(new Request('https://w/nope'), BASE_ENV);
check('unknown route 404', res.status === 404);

/* report ------------------------------------------------------------------ */
let failed = 0;
for (const r of results) {
  if (!r.pass) failed++;
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.pass || !r.detail ? '' : '   <- ' + r.detail}`);
}
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
