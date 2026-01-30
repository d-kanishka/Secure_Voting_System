# Campus E‑Voting — Secure Token-Based Voting System

## Overview

This repository contains a secure, token-based campus voting system. It implements secure authentication (password + TOTP), role-based authorization (voter / admin / auditor), one-time voting tokens, hybrid encryption for vote confidentiality, digital signatures for integrity and an audit trail for transparency.

Key goals:
- Usability: QR provisioning for TOTP, clear login → MFA flow, admin UI to manage elections and eligible voters.
- Security: bcrypt password hashes, TOTP MFA, salted one-time tokens (only hashes stored), AES-GCM encryption for votes, RSA for key transport, RSA-PSS signatures for tamper evidence.
- Separation of duties: server-side role enforcement (never trust the frontend).


## Repo layout

- `backend/`
  - `app.py` — Flask API and main application logic (register, login, TOTP verify, elections, tokens, votes, audit endpoints).
  - `auth.py` — JWT helpers, bcrypt password helpers, role & MFA decorator, JWT error handlers.
  - `models.py` — MongoDB client, collection references, hashing helpers, audit logger.
  - `crypto_utils.py` — RSA/AES/Signing helper functions (key generation, encryption, decryption, signing).
  - `validators.py` — email → role mapping logic.
  - `mail_utils.py` — send emails (SMTP) with dev outbox fallback.
  - `config.py` — configuration values and environment variable definitions.
  - `requirements.txt` — Python dependencies.

- `frontend/` (React)
  - `src/`
    - `auth.js` — token helpers
    - `api.js` — axios client (attach Authorization header)
    - `App.js` — routes
    - `components/` — `Register`, `Login`, `TOTPVerify`, `Dashboard`, `AdminPanel`, `AuditorPanel`, `Navbar`, `ResetPassword`, `Landing`, etc.


## Features

- Registration with email-based role auto-assignment (student → voter, admin domains → admin).
- TOTP MFA with provisioning URI + QR code for easy setup.
- Two-step login: Password → temporary JWT → TOTP verification → final JWT (mfa claim).
- One-time voting tokens:
  - Token shown only once to the user.
  - Server stores only salted hash of token.
  - Token bound to user and election, and removed after use.
- Vote confidentiality:
  - Hybrid encryption: AES-GCM per token + RSA-OAEP to protect AES keys.
  - Votes stored encrypted, and signed (RSA-PSS) to detect tampering.
- Role-based dashboards:
  - Voter: request token, cast vote, view eligible elections.
  - Admin: manage elections, add eligible users, issue tokens (admin-issued), view audit logs, outbox, import users.
  - Auditor: view audit logs, verify vote signatures, view tallies.
- Audit logging for all important actions.



## Dependencies & Installation

### Backend (Python / Flask)

Requirements are in `backend/requirements.txt`. Main packages:

- Flask, flask-jwt-extended, flask-cors
- pymongo
- cryptography
- bcrypt
- pyotp
- qrcode, pillow
- python-dotenv (optional)

Steps:

1. Create virtual environment and activate:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r backend/requirements.txt
   ```

3. Set environment variables (see `.env.example`). At minimum:

   ```
   MONGO_URI=mongodb://localhost:27017/voting_db
   JWT_SECRET_KEY=change-me
   KEY_PASSPHRASE=change-me
   TOTP_ISSUER_NAME="Student E-Voting"
   MFA_WINDOW_SECONDS=300
   RESET_CODE_TTL_SECONDS=600
   SMTP_SERVER=
   SMTP_PORT=587
   SMTP_USER=
   SMTP_PASS=
   FROM_EMAIL=no-reply@example.com
   ```

4. Start the backend:

   ```bash
   cd backend
   python app.py
   ```

### Frontend (React)

1. Install dependencies and start:

   ```bash
   cd frontend
   npm install
   npm start
   ```

2. The frontend expects API root at `REACT_APP_API_URL` (default `http://localhost:5000`). You can set this in `.env` inside `frontend/` or in the environment.


## Database (MongoDB) 

- Start MongoDB (local or remote). Use `MONGO_URI` in env.
- Collections used: `users`, `elections`, `tokens`, `votes`, `audit_logs`, `outbox` (dev), `has_voted`.


## Demo Flow

1. Open the site → Register as a student (email must match `cb.sc.u4cse<id>@cb.students.amrita.edu`) or admin (`@cb.admin.amrita.edu`).
2. On registration you will get a provisioning QR and URI — scan to your authenticator app.
3. Login with password — you will receive a temporary token and must enter TOTP code on the TOTP Verify page.
4. After TOTP verification you will be issued a final access token and redirected to a role-specific dashboard.
5. Admin: create an election; add eligible users; start election.
6. Voter: request a one-time token (only if eligible & recently MFA-verified) → copy token (shown once) → cast vote.
7. Auditor: view tally or verify individual votes and check audit logs.


## API — Key endpoints 

- POST /register — create user (returns provisioning URI + QR)
- POST /login — password step (returns temp_token)
- POST /verify_totp — TOTP verify (requires temp_token) -> returns access_token
- GET /list_elections — list elections (auth required)
- POST /create_election — admin only
- POST /add_eligible_voter — admin only
- POST /issue_token — issue one-time token (voter or admin)
- POST /cast_vote — cast using token (voter)
- POST /publish_results — admin
- POST /audit/verify_vote — auditor: verify vote signature & decrypt one vote
- GET /audit/election_tally/<id> — admin/auditor: per-candidate tally
- POST /forgot_password & POST /reset_password — password recovery
- GET /admin/audit_logs, GET /audit_logs — view logs



## Testing & Troubleshooting

- If TOTP codes fail: ensure device time is synced (set to network automatic time).
- If `verify_totp` returns session expired: temp token TTL is short (default 5 minutes). Re-login and immediately verify TOTP.
- If email reset codes do not arrive: configure SMTP env vars or check `db.outbox` (dev fallback).
- If voter sees "Eligible: No": make sure admin added username to election eligible list (`POST /add_eligible_voter`) or use admin UI to add.
- If double votes occurred earlier: the system now enforces `db.has_voted` and cleans up unused tokens upon cast; duplicates from earlier runs remain (admin can mark invalid if necessary).
- To inspect audit logs: Admin/Auditor UI or GET `/audit_logs`.
