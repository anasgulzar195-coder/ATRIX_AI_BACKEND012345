# ATRIX AI Backend (FastAPI)

Provides registration/login, signed sessions, AI provider proxy, activation-code redemption, plan expiry checks, and basic admin endpoints.

## Deploy
1. Push this folder's contents to a private GitHub repository.
2. Create a Render web service from the repository; build: `pip install -r requirements.txt`; start: `uvicorn atrix_backend.server:app --host 0.0.0.0 --port $PORT`.
3. Set `TOKEN_SECRET` and `ADMIN_API_KEY` to long random secrets; set `CORS_ORIGINS` to the exact website origin(s).
4. Set `DATABASE_URL` to a persistent PostgreSQL connection string for production. SQLite on an ephemeral free web service can lose data after redeploy/restart; do not use it for real accounts or plans.
5. Configure provider keys as environment secrets if you want server-managed keys. Desktop users may send their own API key to `/v1/chat`; keys are not written to the event log.

## API
- `GET /health`
- `POST /v1/auth/register` `{username,email,password}`
- `POST /v1/auth/login` `{email,password}`
- `GET /v1/me` with `Authorization: Bearer <token>`
- `POST /v1/license/activate` `{code}` with bearer token
- `POST /v1/chat` `{provider,message,history,api_key,language}` with bearer token
- `POST /v1/admin/activation-codes` with `X-Admin-Key` and `{plan,days,count}`
- `GET /v1/admin/users` with `X-Admin-Key`
- `POST /v1/admin/users/{id}/suspend` with `X-Admin-Key`

## Important
This is an initial deployable backend, not a payment gateway. A human must verify JazzCash/Easypaisa/bank payments and issue activation codes, or a trusted payment provider/webhook must be added. Protect admin secrets, enable HTTPS, use PostgreSQL, backups, rate limits, and a privacy policy before public launch. Never put `ADMIN_API_KEY` in the website JavaScript.
