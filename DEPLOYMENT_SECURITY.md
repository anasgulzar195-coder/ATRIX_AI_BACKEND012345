# Deployment security checklist
- HTTPS only; set strong TOKEN_SECRET and ADMIN_API_KEY in hosting dashboard.
- PostgreSQL with backups for production. Do not use ephemeral SQLite for paid plans.
- Restrict CORS to the exact website origin.
- Add request rate limits, email verification, password reset, audit-log retention policy, and abuse protection before a public launch.
- Do not accept client-supplied payment status as proof. Verify receipts manually or use a payment provider webhook.
- The current plan system expires access when `/v1/chat` is called and `expires_at` is in the past; schedule a periodic status update if the website must display an expired label without a login/chat request.
