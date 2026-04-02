# Cloudflare Worker Setup Guide

## Step 1 — Create Cloudflare account
Go to https://cloudflare.com and sign up (free)

## Step 2 — Generate VAPID keys
Go to https://vapidkeys.com
Copy the Public Key and Private Key

## Step 3 — Update worker.js
Open worker.js and fill in:
- VAPID_PRIVATE_KEY = your private key from vapidkeys.com
- VAPID_PUBLIC_KEY  = your public key from vapidkeys.com  
- VAPID_SUBJECT     = mailto:your@email.com
- APP_URL           = your GitHub Pages URL

## Step 4 — Update index.html
In index.html find:
  const VAPID_PUBLIC_KEY = 'REPLACE_WITH_YOUR_VAPID_PUBLIC_KEY';
  const WORKER_URL = 'REPLACE_WITH_YOUR_WORKER_URL';

Replace with your actual VAPID public key and Worker URL

## Step 5 — Deploy the Worker
1. Install Wrangler: npm install -g wrangler
2. Login: wrangler login
3. Create KV namespace: wrangler kv:namespace create PUSH_SUBS
4. Copy the ID shown and paste it in wrangler.toml
5. Deploy: wrangler deploy

Your Worker URL will be:
  https://device-status-worker.YOUR_SUBDOMAIN.workers.dev

## Step 6 — Test it
Open: https://device-status-worker.YOUR_SUBDOMAIN.workers.dev/test
This manually triggers a check and sends notifications

## Step 7 — Enable notifications in the app
Open your app → click the bell (Notify) button in the topbar
Allow notifications when prompted
You will now receive alerts for High priority devices 9am–6pm IST

## Cron schedule
The worker runs automatically every 2 hours.
To change frequency, edit wrangler.toml:
  "0 */2 * * *"  = every 2 hours
  "0 * * * *"    = every hour
  "0 */4 * * *"  = every 4 hours
