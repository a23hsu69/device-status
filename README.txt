# Device Status — Kochi Region PWA

## Files
- index.html   — the entire app (open this)
- sw.js        — service worker (offline support)
- manifest.json — PWA manifest (install on Android/PC)
- icons/       — app icons
- serve.bat    — one-click local server for Windows

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
  or menu → Install Device Status

─── Offline behaviour ──────────────────────────────
  After first load the app works fully offline.
  Device data is cached from the last fetch.
  Engineer assignments and remarks are stored forever.

─── CSV API CORS note ──────────────────────────────
  If fetch fails, the app uses cached data.
  To fix permanently, ask your server admin to add:
  Access-Control-Allow-Origin: *
