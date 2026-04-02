# Field Manager — Kochi Region PWA  (v6.0)

## Files
- index.html    — the entire app (open this)
- sw.js         — service worker (offline support, push notifications)
- manifest.json — PWA manifest (install on Android/PC)
- worker.js     — Cloudflare Worker backend (deploy separately)
- icons/        — app icons
- serve.bat     — one-click local server for Windows

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  !! DO NOT open index.html by double-clicking !!
  Service workers require a local server (http://)
  not a file:// URL. Use one of the methods below.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

─── Option A: serve.bat (simplest, Windows) ────────
  1. Make sure Python is installed:
     https://www.python.org/downloads/
     (tick "Add Python to PATH" during install)
  2. Double-click serve.bat inside this folder
  3. Open Chrome and go to: http://localhost:8000

─── Option B: VS Code Live Server ──────────────────
  1. Install VS Code: https://code.visualstudio.com
  2. Install the "Live Server" extension
  3. Right-click index.html → Open with Live Server

─── Option C: Host on GitHub Pages (free) ──────────
  1. Create account at https://github.com
  2. New repository → upload all these files
  3. Settings → Pages → Deploy from branch → main
  4. Access at: https://yourusername.github.io/repo/

─── Install on Android ─────────────────────────────
  Open the app URL in Chrome on your phone
  → tap menu (⋮) → Add to Home Screen

─── Install on PC (Chrome/Edge) ────────────────────
  Open the app URL → look for ⊕ in the address bar
  or menu → Install Field Manager

─── Offline behaviour ──────────────────────────────
  After first load the app works fully offline.
  Device list is cached from the last KV sync.
  Engineer assignments and remarks are stored forever.

─── Device list setup (admin) ──────────────────────
  Log in as admin → Settings (⚙) → Device list section

  Three ways to populate the device list:
  1. Add manually — enter site name, MAC ID, and label one by one
  2. Upload CSV — upload a CSV file; app shows a diff preview
     (new / removed / unchanged) before you apply it
  3. Fetch from URL — paste the CSV endpoint URL and tap
     "Fetch now"; the Cloudflare Worker fetches it server-side
     (no CORS issues) and saves the result to KV

  After any change, tap "Save devices to server" to push
  the list to KV so all engineers see it on next login.

─── Cloudflare Worker endpoints (v6.0) ─────────────
  GET  /device-list        — fetch full device list + version
  POST /device-list        — save device list to KV
  POST /set-fetch-url      — save CSV fetch URL to KV
  GET  /fetch-from-url     — trigger one-time CSV fetch from stored URL
  POST /subscribe          — register push subscription
  POST /unsubscribe        — remove push subscription
  POST /manual-alert       — send push + store in KV inbox
  GET  /inbox?user=X       — get notification history for user
  POST /clear-inbox        — clear a user's inbox
  GET  /get-credentials    — fetch credential map
  POST /set-credentials    — update engineer credentials + roles
  POST /set-admin-password — change admin password
  POST /submit-report      — engineer submits a report
  GET  /get-reports        — admin fetches all reports
  POST /submit-leave       — engineer submits leave request
  GET  /get-leaves         — admin fetches leave requests
  POST /update-leave       — admin approves/declines leave
  POST /submit-visit       — engineer submits visit request
  GET  /get-visits         — admin fetches visit requests
  GET  /get-sites          — fetch distant sites list
  POST /set-sites          — save distant sites list
  GET  /get-contacts       — fetch mail contacts
  POST /set-contacts       — save mail contacts
  GET  /get-visit-contacts — fetch visit mail contacts
  POST /set-visit-contacts — save visit mail contacts
  POST /gmail-draft        — proxy to Google Apps Script

─── What changed in v6.0 ───────────────────────────
  • Device status polling removed (CSV API no longer available)
  • Device list now managed by admin in Settings and synced via KV
  • Four new worker endpoints for device list management
  • Searchable site picker in report wizard (was a plain dropdown)
  • Device labels shown in report wizard (e.g. "IN/OUT LHS — MAC")
  • "Select all devices" checkbox in report wizard
  • Admin gets push notification when engineer submits any report
  • Bug fix: new users can now log in after being added by admin
  • Bug fix: role changes (engineer ↔ admin) now sync correctly to KV
  • Bug fix: Swethaswan's visit requests now reach admin panel
  • App renamed to "Field Manager"

─── v5 → v6 migration note ────────────────────────
  Existing push subscriptions, notification history, reports,
  leave requests, and visit requests are all preserved in KV.
  The only data that is NOT migrated is the old device status
  cache in localStorage (key: dsc_lastdata_v1) — this is no
  longer used and can be cleared manually if needed.
  The new service worker cache (dsc-v60) replaces dsc-v45
  automatically on first load.
