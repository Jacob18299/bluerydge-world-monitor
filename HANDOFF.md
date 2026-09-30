# Bluerydge World Monitor — Publish Hand-off

This folder contains everything needed to put the World Monitor dashboard live on the web.

## What's in here
- **index.html** — the entire dashboard as ONE self-contained file. No build step, no
  dependencies, works offline. This is the file that gets published.
- **HANDOFF.md** — this guide.
- **prompt-1-publish.txt** — paste into Claude Code to publish the site (Phase 1).
- **prompt-2-livedata.txt** — paste into Claude Code later to wire live feeds (Phase 2).

## The plan (same accounts as the newsletter — no new signups)
Publishing has three parts. Your boss was right that Cloudflare comes back — but only as the
*host*. Claude Code does the actual work; it just deploys *to* Cloudflare.

1. **Website hosting → Cloudflare Pages.** Serves index.html to the world 24/7 on a real URL.
2. **Live TV → already works.** The channels are browser-side stream embeds; no backend needed.
3. **Live data → Cloudflare Worker (cron).** Fetches real news/threat feeds on a schedule and
   refreshes the signals. This is the only part that's a real build — do it as Phase 2.

### Recommended order
- **Phase 1 (today): Publish.** Get index.html live on Cloudflare Pages. The dashboard looks and
  behaves exactly as it does now, on representative data. Shareable URL, done in minutes.
- **Phase 2 (later): Live data.** Add the Worker that replaces the sample signals with real feeds.

This way you have a live, shareable, great-looking site immediately, and the harder live-data
work happens as a clearly-scoped follow-up — not a blocker.

## How to run Phase 1
1. Open **Terminal**, then start Claude Code (`claude`).
2. Make sure this `publish` folder is the project Claude Code is working in (or copy index.html
   into your repo).
3. Paste the contents of **prompt-1-publish.txt** and follow its steps.
4. When it finishes, it gives you a `*.pages.dev` URL — that's your live dashboard.

## Phase 2 (when you're ready)
Paste **prompt-2-livedata.txt** into Claude Code. It explains the data model the dashboard
expects so the Worker can feed it real signals without redesigning anything.

## Custom domain (optional, later)
Once it's on Pages, a custom URL like `monitor.bluerydge.com` is a 2-minute step in the
Cloudflare dashboard (Pages → your project → Custom domains). Needs whoever manages the
bluerydge.com DNS to approve it — same as the email-sender question.
