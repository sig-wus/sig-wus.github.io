/**
 * SIG-WUS sign-up Worker
 * =====================================================================
 * Two opt-in modes, selected by the OPT_IN_MODE variable in wrangler.toml:
 *
 *   "single" (default)  submit -> subscriber is written to Infomaniak right
 *                       away and the modal says "you are on the list".
 *                       Consent evidence (timestamp, IP, form) is stored in
 *                       the subscriber's fields. Optional welcome mail.
 *                       No inbox round-trip. SMTP is only needed if
 *                       WELCOME_MAIL or NOTIFY_EMAIL is used.
 *
 *   "double"            submit -> HMAC-signed confirmation link is mailed,
 *                       nothing is stored; the subscriber is only created
 *                       when that link is opened. Strongest proof of consent
 *                       and the safest option for German recipients.
 *
 * Routes
 *   POST /subscribe   form intake (JSON or url-encoded)
 *   GET  /confirm     redeems a confirmation link (double mode only)
 *   GET  /health      liveness check
 *
 * Abuse control in both modes: hidden honeypot field, optional Turnstile,
 * server-side group allowlist, and an MX lookup that rejects addresses whose
 * domain cannot receive mail (catches @gmial.com before it becomes a bounce).
 */

import { WorkerMailer } from 'worker-mailer';

/* ---------------------------------------------------------------- config -- */

/* Checkbox keys -> values written into the Infomaniak "SIG Area" subscriber
   field (key: sig-area). Panel segments match these through their "contains"
   filter lines. Legacy survey values (Standardization, Conference
   Organization, Young Academics & Teaching, Exchange Platform) are matched by
   the segments' equality lines and are NEVER written by this worker.
   Note: PLATFORM deliberately stores "Open Exchange Platform", not "Exchange
   Platform", so new platform sign-ups do not hit the legacy equality line in
   the Industry & Clinical Translation segment. */
const AREA_NAMES = {
  EVENTS: 'Events & Education',
  INDUSTRY: 'Industry & Clinical Translation',
  STANDARDS: 'Standards & Regulatory',
  PLATFORM: 'Open Exchange Platform',
};
const BASE_GROUP = 'sig-wus community';  // the single group; targeting happens via segments
const LINK_TTL_MS = 48 * 60 * 60 * 1000; // confirmation link lifetime
const MAX_BODY = 8 * 1024;               // reject oversized posts
const EMAIL_RE = /^[^\s@,;<>]+@[^\s@,;<>]+\.[A-Za-z]{2,}$/;
const LIMITS = { email: 150, firstname: 80, lastname: 80, affiliation: 150, country: 60 };
/* Server-side country allowlist; must mirror the <select> options in the
   site's index.html sign-up form. */
const COUNTRIES = new Set([
  'Afghanistan', 'Albania', 'Algeria', 'Andorra', 'Angola',
  'Antigua and Barbuda', 'Argentina', 'Armenia', 'Australia', 'Austria',
  'Azerbaijan', 'Bahamas', 'Bahrain', 'Bangladesh', 'Barbados',
  'Belarus', 'Belgium', 'Belize', 'Benin', 'Bermuda',
  'Bhutan', 'Bolivia', 'Bosnia and Herzegovina', 'Botswana', 'Brazil',
  'Brunei', 'Bulgaria', 'Burkina Faso', 'Burundi', 'Cabo Verde',
  'Cambodia', 'Cameroon', 'Canada', 'Central African Republic', 'Chad',
  'Chile', 'China', 'Colombia', 'Comoros', 'Congo (Democratic Republic)',
  'Congo (Republic)', 'Costa Rica', 'Cote d\'Ivoire', 'Croatia', 'Cuba',
  'Cyprus', 'Czechia', 'Denmark', 'Djibouti', 'Dominica',
  'Dominican Republic', 'Ecuador', 'Egypt', 'El Salvador', 'Equatorial Guinea',
  'Eritrea', 'Estonia', 'Eswatini', 'Ethiopia', 'Faroe Islands',
  'Fiji', 'Finland', 'France', 'Gabon', 'Gambia',
  'Georgia', 'Germany', 'Ghana', 'Greece', 'Greenland',
  'Grenada', 'Guam', 'Guatemala', 'Guinea', 'Guinea-Bissau',
  'Guyana', 'Haiti', 'Honduras', 'Hong Kong', 'Hungary',
  'Iceland', 'India', 'Indonesia', 'Iran', 'Iraq',
  'Ireland', 'Israel', 'Italy', 'Jamaica', 'Japan',
  'Jordan', 'Kazakhstan', 'Kenya', 'Kiribati', 'Kosovo',
  'Kuwait', 'Kyrgyzstan', 'Laos', 'Latvia', 'Lebanon',
  'Lesotho', 'Liberia', 'Libya', 'Liechtenstein', 'Lithuania',
  'Luxembourg', 'Macao', 'Madagascar', 'Malawi', 'Malaysia',
  'Maldives', 'Mali', 'Malta', 'Marshall Islands', 'Mauritania',
  'Mauritius', 'Mexico', 'Micronesia', 'Moldova', 'Monaco',
  'Mongolia', 'Montenegro', 'Morocco', 'Mozambique', 'Myanmar',
  'Namibia', 'Nauru', 'Nepal', 'Netherlands', 'New Zealand',
  'Nicaragua', 'Niger', 'Nigeria', 'North Korea', 'North Macedonia',
  'Norway', 'Oman', 'Pakistan', 'Palau', 'Palestine',
  'Panama', 'Papua New Guinea', 'Paraguay', 'Peru', 'Philippines',
  'Poland', 'Portugal', 'Puerto Rico', 'Qatar', 'Romania',
  'Russia', 'Rwanda', 'Saint Kitts and Nevis', 'Saint Lucia', 'Saint Vincent and the Grenadines',
  'Samoa', 'San Marino', 'Sao Tome and Principe', 'Saudi Arabia', 'Senegal',
  'Serbia', 'Seychelles', 'Sierra Leone', 'Singapore', 'Slovakia',
  'Slovenia', 'Solomon Islands', 'Somalia', 'South Africa', 'South Korea',
  'South Sudan', 'Spain', 'Sri Lanka', 'Sudan', 'Suriname',
  'Sweden', 'Switzerland', 'Syria', 'Taiwan', 'Tajikistan',
  'Tanzania', 'Thailand', 'Timor-Leste', 'Togo', 'Tonga',
  'Trinidad and Tobago', 'Tunisia', 'Turkey', 'Turkmenistan', 'Tuvalu',
  'Uganda', 'Ukraine', 'United Arab Emirates', 'United Kingdom', 'United States',
  'Uruguay', 'Uzbekistan', 'Vanuatu', 'Vatican City', 'Venezuela',
  'Vietnam', 'Yemen', 'Zambia', 'Zimbabwe'
]);

/* --------------------------------------------------------------- helpers -- */

const enc = new TextEncoder();

function b64urlEncode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
}

async function sign(payloadB64, secret) {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(payloadB64));
  return b64urlEncode(new Uint8Array(sig));
}

/** constant-time string compare */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function clean(value, max) {
  return String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .slice(0, max);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function corsHeaders(env, origin) {
  const list = allowedOrigins(env);
  const ok = origin && list.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? origin : list[0] || '',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function json(env, origin, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(env, origin) },
  });
}

function htmlPage(status, title, body, env) {
  const site = env.SITE_URL || 'https://sig-wus.org';
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:#E7EEF4;color:#1A2E40;
display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}
.c{background:#fff;border:1px solid #C9D8E3;border-radius:14px;padding:28px 30px;max-width:460px;margin:20px}
h1{font-size:20px;margin:0 0 10px}p{margin:0 0 12px;line-height:1.55}a{color:#00629B}</style></head>
<body><div class="c"><h1>${escapeHtml(title)}</h1>${body}
<p><a href="${escapeHtml(site)}">Back to sig-wus.org</a></p></div></body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

/* ----------------------------------------------------------------- mail --- */

async function sendMail(env, to, subject, text, html) {
  const mailer = await WorkerMailer.connect({
    host: env.SMTP_HOST,
    port: Number(env.SMTP_PORT || 587),
    secure: Number(env.SMTP_PORT) === 465,
    startTls: Number(env.SMTP_PORT) !== 465,
    credentials: { username: env.SMTP_USER, password: env.SMTP_PASS },
    authType: ['plain', 'login'],
  });
  try {
    await mailer.send({
      from: { name: env.FROM_NAME || 'SIG-WUS', email: env.FROM_EMAIL },
      to,
      subject,
      text,
      html,
    });
  } finally {
    if (typeof mailer.close === 'function') await mailer.close();
  }
}

/* -------------------------------------------------------------- turnstile -- */

async function turnstileOk(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true; // not configured -> skip
  const body = new FormData();
  body.append('secret', env.TURNSTILE_SECRET);
  body.append('response', token || '');
  if (ip) body.append('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body,
  });
  const out = await res.json().catch(() => ({ success: false }));
  return out.success === true;
}

/* ---------------------------------------------------------- mx pre-check -- */

/** Reject domains that cannot receive mail at all (typos, throwaways). */
async function domainAcceptsMail(email) {
  const domain = email.split('@')[1];
  if (!domain) return false;
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      { headers: { accept: 'application/dns-json' } }
    );
    if (!res.ok) return true; // resolver problem -> do not punish the user
    const dns = await res.json();
    if (Array.isArray(dns.Answer) && dns.Answer.some((a) => a.type === 15)) return true;
    // some small domains have no MX and rely on the A record
    const a = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { accept: 'application/dns-json' } }
    ).then((r) => (r.ok ? r.json() : { Answer: [] }));
    return Array.isArray(a.Answer) && a.Answer.length > 0;
  } catch {
    return true; // never block a sign-up because DNS hiccuped
  }
}

/* ---------------------------------------------------- infomaniak write ----- */

async function writeSubscriber(env, sub, areaKeys, consentMs, ip) {
  const areas = areaKeys.map((g) => AREA_NAMES[g]).filter(Boolean);
  const fields = {
    firstname: sub.firstname,
    lastname: sub.lastname,
    affiliation: sub.affiliation,
    country: sub.country,
    /* panel field keys are slugified with hyphens, not underscores */
    'consent-at': new Date(consentMs).toISOString(),
    'consent-source':
      `sig-wus.org sign-up form (${env.OPT_IN_MODE === 'double' ? 'double' : 'single'} opt-in` +
      (ip ? `, ip ${ip}` : '') + ')',
  };
  // Only write SIG Area when something was picked: a re-subscribing legacy
  // member with no selection must keep their existing value and segments.
  if (areas.length) fields['sig-area'] = areas.join('; ');
  const res = await fetch(`https://api.infomaniak.com/1/newsletters/${env.IK_DOMAIN_ID}/subscribers`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.IK_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: sub.email,
      fields,
      groups: [BASE_GROUP],
    }),
  });
  if (!res.ok) {
    console.error('infomaniak error', res.status, await res.text());
    return { ok: false, areas };
  }
  return { ok: true, areas };
}

async function notifyManager(env, sub, areas, consentMs) {
  if (!env.NOTIFY_EMAIL) return;
  try {
    await sendMail(
      env,
      env.NOTIFY_EMAIL,
      `New SIG-WUS sign-up: ${sub.firstname} ${sub.lastname}`,
      `${sub.firstname} ${sub.lastname} <${sub.email}>\n` +
        `${sub.affiliation}, ${sub.country}\n` +
        `Areas: ${areas.join(', ')}\n` +
        `Consent: ${new Date(consentMs).toISOString()}\n`,
      null
    );
  } catch (err) {
    console.error('notify failed', err && err.message); // never fail the user for this
  }
}

/* -------------------------------------------------------------- handlers -- */

async function readBody(request) {
  const type = request.headers.get('Content-Type') || '';
  const raw = await request.text();
  if (raw.length > MAX_BODY) throw new Error('body too large');
  if (type.includes('application/json')) {
    const obj = JSON.parse(raw);
    return { form: false, data: obj, groups: Array.isArray(obj.groups) ? obj.groups : [] };
  }
  const params = new URLSearchParams(raw);
  const obj = Object.fromEntries(params.entries());
  return { form: true, data: obj, groups: params.getAll('groups') };
}

async function handleSubscribe(request, env, origin) {
  let parsed;
  try {
    parsed = await readBody(request);
  } catch {
    return json(env, origin, 400, { error: 'Malformed request.' });
  }
  const { form, data } = parsed;
  const okTitle = String(env.OPT_IN_MODE || 'single') === 'double' ? 'Check your inbox' : 'You are on the list';
  const reply = (status, body) =>
    form
      ? htmlPage(status, status < 400 ? okTitle : 'Sign-up failed',
          `<p>${escapeHtml(body.message || body.error)}</p>`, env)
      : json(env, origin, status, body);

  // 1. spam trap -- pretend everything is fine so bots do not retry
  if (clean(data.website, 200) !== '') {
    return reply(200, { ok: true, message: 'Please check your inbox for the confirmation link.' });
  }

  // 2. field validation
  const sub = {
    email: clean(data.email, LIMITS.email).toLowerCase(),
    firstname: clean(data.firstname, LIMITS.firstname),
    lastname: clean(data.lastname, LIMITS.lastname),
    affiliation: clean(data.affiliation, LIMITS.affiliation),
    country: clean(data.country, LIMITS.country),
  };
  if (!EMAIL_RE.test(sub.email)) return reply(400, { error: 'Please enter a valid e-mail address.' });
  if (!sub.firstname || !sub.lastname) return reply(400, { error: 'Please enter your name.' });
  if (!sub.affiliation || !sub.country) return reply(400, { error: 'Please enter affiliation and country.' });
  if (!COUNTRIES.has(sub.country)) return reply(400, { error: 'Please select your country from the list.' });
  const consent = data.consent === true || clean(data.consent, 10) === 'yes' || clean(data.consent, 10) === 'true';
  if (!consent) return reply(400, { error: 'Please confirm the consent checkbox.' });

  // 3. groups: server-side allowlist, never trust the client
  const groups = [...new Set(parsed.groups.map((g) => clean(g, 20)))].filter((g) => g in AREA_NAMES);

  // 4. bot check
  const ip = request.headers.get('CF-Connecting-IP') || '';
  if (!(await turnstileOk(env, data.turnstile || data['cf-turnstile-response'], ip))) {
    return reply(400, { error: 'Bot check failed. Please reload the page and try again.' });
  }

  // 5. address must belong to a domain that can actually receive mail
  if (!(await domainAcceptsMail(sub.email))) {
    return reply(400, { error: 'That e-mail domain does not accept mail. Please check for a typo.' });
  }

  const now = Date.now();

  /* ================= single opt-in: write immediately ==================== */
  if (String(env.OPT_IN_MODE || 'single') !== 'double') {
    const written = await writeSubscriber(env, sub, groups, now, ip);
    if (!written.ok) {
      return reply(502, { error: 'We could not save your sign-up. Please write to contact@sig-wus.org.' });
    }
    if (env.WELCOME_MAIL === '1') {
      const picked = groups.length ? groups.map((g) => AREA_NAMES[g]).join(', ') : 'none selected';
      try {
        await sendMail(
          env,
          [{ name: `${sub.firstname} ${sub.lastname}`, email: sub.email }],
          'Welcome to the SIG-WUS community',
          `Hello ${sub.firstname},\n\nyou are now on the SIG-WUS community list.\n` +
            `Working groups: ${picked}.\n\n` +
            `If this was not you, reply to this mail and we will remove the address immediately.\n\n` +
            `SIG-WUS - ${env.SITE_URL}\n`,
          `<p>Hello ${escapeHtml(sub.firstname)},</p>` +
            `<p>you are now on the SIG-WUS community list. Working groups: ${escapeHtml(picked)}.</p>` +
            `<p style="font-size:13px;color:#51677A">If this was not you, reply to this mail and we will ` +
            `remove the address immediately.<br>SIG-WUS &mdash; ` +
            `<a href="${escapeHtml(env.SITE_URL)}">${escapeHtml(env.SITE_URL)}</a></p>`
        );
      } catch (err) {
        console.error('welcome mail failed', err && err.message); // not fatal
      }
    }
    await notifyManager(env, sub, written.areas, now);
    return reply(200, {
      ok: true,
      message: `You are on the list, ${sub.firstname}. Welcome to SIG-WUS.`,
    });
  }

  /* ================= double opt-in: mail a signed link =================== */
  // sign the payload -- this is the consent token
  const payload = { s: sub, g: groups, t: now, ip: ip.slice(0, 45) };
  const p = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await sign(p, env.HMAC_SECRET);
  const link = `${env.PUBLIC_URL}/confirm?d=${p}&s=${sig}`;

  const picked = groups.length ? groups.map((g) => AREA_NAMES[g]).join(', ') : 'none selected';
  const text =
    `Hello ${sub.firstname},\n\n` +
    `please confirm that you want to join the SIG-WUS community mailing list:\n\n${link}\n\n` +
    `The link is valid for 48 hours. Working groups selected: ${picked}.\n\n` +
    `If you did not request this, simply ignore this message - nothing has been stored.\n\n` +
    `SIG-WUS - ${env.SITE_URL}\n`;
  const html =
    `<p>Hello ${escapeHtml(sub.firstname)},</p>` +
    `<p>please confirm that you want to join the SIG-WUS community mailing list:</p>` +
    `<p><a href="${escapeHtml(link)}" style="background:#00629B;color:#fff;padding:11px 22px;` +
    `border-radius:9px;text-decoration:none;font-weight:600;display:inline-block">Confirm my sign-up</a></p>` +
    `<p style="font-size:13px;color:#51677A">The link is valid for 48 hours. Working groups selected: ` +
    `${escapeHtml(picked)}.<br>If you did not request this, simply ignore this message &mdash; nothing has been stored.</p>` +
    `<p style="font-size:13px;color:#51677A">SIG-WUS &mdash; ` +
    `<a href="${escapeHtml(env.SITE_URL)}">${escapeHtml(env.SITE_URL)}</a></p>`;

  try {
    await sendMail(env, [{ name: `${sub.firstname} ${sub.lastname}`, email: sub.email }],
      'Please confirm your SIG-WUS sign-up', text, html);
  } catch (err) {
    console.error('smtp failed', err && err.message);
    return reply(502, { error: 'We could not send the confirmation e-mail. Please try again later.' });
  }

  return reply(200, { ok: true, message: 'Please check your inbox for the confirmation link.' });
}

async function handleConfirm(url, env) {
  const p = url.searchParams.get('d') || '';
  const s = url.searchParams.get('s') || '';
  const expected = await sign(p, env.HMAC_SECRET);
  if (!safeEqual(s, expected)) {
    return htmlPage(400, 'Invalid link', '<p>This confirmation link is not valid. Please sign up again.</p>', env);
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
  } catch {
    return htmlPage(400, 'Invalid link', '<p>This confirmation link is damaged. Please sign up again.</p>', env);
  }
  if (!payload.t || Date.now() - payload.t > LINK_TTL_MS) {
    return htmlPage(410, 'Link expired', '<p>This confirmation link is older than 48 hours. Please sign up again.</p>', env);
  }

  const sub = payload.s;
  const written = await writeSubscriber(env, sub, payload.g || [], payload.t, payload.ip || '');
  if (!written.ok) {
    return htmlPage(
      502,
      'Something went wrong',
      '<p>Your confirmation was valid but we could not save it. Please write to ' +
        '<a href="mailto:contact@sig-wus.org">contact@sig-wus.org</a>.</p>',
      env
    );
  }

  await notifyManager(env, sub, written.areas, payload.t);
  return Response.redirect(`${env.SITE_URL}/?subscribed=1`, 302);
}

/* ------------------------------------------------------------------ main -- */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, origin) });
    }
    if (url.pathname === '/subscribe' && request.method === 'POST') {
      // reject cross-origin XHR from anywhere but the site (form posts send no Origin match)
      const list = allowedOrigins(env);
      if (origin && list.length && !list.includes(origin)) {
        return json(env, origin, 403, { error: 'Forbidden origin.' });
      }
      return handleSubscribe(request, env, origin);
    }
    if (url.pathname === '/confirm' && request.method === 'GET') {
      return handleConfirm(url, env);
    }
    if (url.pathname === '/health') {
      return new Response('ok', { status: 200 });
    }
    return new Response('Not found', { status: 404 });
  },
};
