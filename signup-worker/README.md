# SIG-WUS sign-up Worker

Connects the "Join the community" form on `sig-wus.org` (static, GitHub Pages) to the
Infomaniak newsletter, with working-group selection.

**`OPT_IN_MODE = "single"` (default) — no inbox round-trip**

```
browser form ──POST /subscribe──▶ Worker ──API──▶ Infomaniak (active, with groups)
                              ◀── "You are on the list, Ada."
```

Consent evidence (timestamp, IP, form) is written into the subscriber's fields.
Optional welcome mail gives a "this was not me" exit.

**`OPT_IN_MODE = "double"` — confirmation link**

```
browser form ──POST /subscribe──▶ Worker ──SMTP──▶ confirmation mail
                                     │
        user clicks link ────GET /confirm───▶ verify HMAC ──API──▶ Infomaniak
                                     └──────── 302 ──▶ sig-wus.org/?subscribed=1
```

Nothing is stored before confirmation. The HMAC-signed link *is* the consent record:
only this Worker can produce it, and only the owner of the mailbox can redeem it.
Flip the variable in `wrangler.toml` and redeploy to switch; the page needs no change.

The API token never reaches the browser in either mode.

Run `npm test` for the 22-check integration suite (no npm install required — it stubs
SMTP and the network).

## 1. Prepare Infomaniak

```bash
export IK_TOKEN=...                       # token with newsletter scope
python ../tools/ik_newsletter.py domains          # confirm IK_DOMAIN_ID (probably 64876)
python ../tools/ik_newsletter.py ensure-groups 64876
python ../tools/ik_newsletter.py fields  64876    # create missing fields in the panel
```

Fields the Worker writes: `firstname`, `lastname`, `affiliation`, `country`,
`consent_at`, `consent_source`. Create them under **Subscribers → fields** with exactly
these keys (unknown keys are ignored, so a typo silently loses data — check with the
`fields` command).

SMTP needs a mailbox password for `contact@sig-wus.org`. If 2FA is on the account,
generate an *application password* in the Infomaniak manager instead of using the login one.

## 2. Deploy

```bash
npm install
npx wrangler login
npx wrangler secret put IK_TOKEN
npx wrangler secret put HMAC_SECRET      # openssl rand -base64 48
npx wrangler secret put SMTP_PASS
npx wrangler deploy
```

Deploy prints the Worker URL. Put it in **two** places:

* `wrangler.toml` → `PUBLIC_URL`, then `npx wrangler deploy` again
* `index.html` → the `action` attribute of `<form id="join-form">`

A custom route (`api.sig-wus.org`) is nicer than `*.workers.dev` and avoids the
subdomain appearing in confirmation mails; add it under Workers → Routes.

## 3. Optional: Turnstile

Create a Turnstile widget for `sig-wus.org`, then:

* `npx wrangler secret put TURNSTILE_SECRET`
* in `index.html`, add before the submit button:
  `<div class="cf-turnstile" data-sitekey="0x..."></div>`
  and `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`

Without the secret the check is skipped; the hidden honeypot field still runs.

## 4. Test

```bash
curl -X POST https://<worker>/subscribe \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.org","firstname":"A","lastname":"B",
       "affiliation":"ETH","country":"CH","consent":true,"groups":["WG1","WG3"]}'
npx wrangler tail          # live logs while you click the link in the mail
python ../tools/ik_newsletter.py subscribers 64876
```

Checklist: mail arrives, link confirms, subscriber appears with status *active* and the
right groups, second click on the same link is harmless (the API upserts), a link older
than 48 h is rejected.

## Notes and limits

* **Rate limiting** is not in the Worker. Add a Cloudflare WAF rate-limiting rule on
  `/subscribe` (e.g. 5 requests / minute / IP) — cheaper and harder to bypass than app code.
* **Unsubscribes and bounces** stay entirely with Infomaniak; the Worker never touches them.
* **Third-party sign-ups** are blocked by design: an address is only added after someone
  with access to that mailbox clicks the link.
* **Failure mode**: if SMTP is down the user gets a clear error and no data is lost, since
  nothing was written yet.
