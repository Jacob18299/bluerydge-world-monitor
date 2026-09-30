# Bluerydge World Monitor — Phase 2 (Live Data) Notes

The dashboard is now connected to **real, auto-refreshing data**. Nothing about the
look, layout, colours, filters, ticker or AI assistant changed.

## Live URL (unchanged)
https://bluerydge-world-monitor.pages.dev

## What's running now (two pieces, both on the free Cloudflare tier)
1. **A collector Worker** — `bluerydge-monitor-cron`
   - URL: https://bluerydge-monitor-cron.jacob-pakkiyaretnam.workers.dev
   - Wakes up **every 15 minutes**, fetches the feeds, reshapes them, and saves the
     result. You never need to touch it.
   - Data endpoint the dashboard reads: `…workers.dev/api/signals`
   - Manual refresh (optional): open `…workers.dev/refresh` in a browser to force an
     immediate pull.
2. **A shared store (Cloudflare KV)** — holds the latest data blob (`signals-latest`).

## The feeds it pulls
- **CISA KEV** — vulnerabilities being actively exploited (→ Vulnerabilities panel)
- **NVD** — adds CVSS severity scores to those vulnerabilities
- **The Hacker News + BleepingComputer + CISA advisories** — cyber news signals
- **ACSC (Australia)** — Australian cyber advisories
- **GDELT** — geopolitical / conflict events with real locations (→ map pins)

## The AI assistant (now working)
The dashboard's chat assistant was originally built for Claude's preview environment
(`window.claude.complete`), which doesn't exist on a public website — so on the live
site it used to show a canned "I can't reach the AI service" message. It's now wired
to **free Cloudflare Workers AI** via `POST …workers.dev/api/assistant` (the collector
Worker). No API key, no new account, no card — it runs on your existing free tier
(Llama models, with a generous daily free allowance). If the AI is ever unreachable,
the chat shows a brief "please try again" message instead of breaking.

## How it fails safely
If the Worker or the data is ever unavailable, the dashboard automatically falls back
to its original built-in sample data — so the page can never look broken.

## The only change made to the dashboard
A small `loadLiveSignals()` step runs once on page load: it fetches `/api/signals`
and, if it succeeds, swaps the live `EVENTS` / `VULNS` / `REGIONS` in and re-renders.
The pristine Phase-1 file is saved as `index.html.phase1-backup`.

## How to re-deploy if you ever change things
- **The dashboard (index.html):**
  ```
  cp index.html dist/index.html
  npx wrangler pages deploy dist --project-name bluerydge-world-monitor --branch main
  ```
- **The collector Worker (worker/src/index.js — e.g. to add/remove a feed):**
  ```
  cd worker
  npx wrangler deploy
  ```

## Honest caveats (nothing broken — just good to know)
- A vulnerability shows `KEV` instead of a number when NVD doesn't yet have a CVSS
  score for it; real scores fill in automatically over the following refreshes.
- "x minutes ago" times are stamped at fetch time, so they can be up to 15 min behind.
- The Regional Risk Index is computed from how many/how severe the current events are,
  so the numbers move run-to-run (that's the point — it's live now).
