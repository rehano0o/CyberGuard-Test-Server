# CyberGuard Test Server

## Purpose
The controlled web application that the future **CyberGuard SOC** will monitor. It performs real authentication and records real activity as security events. It does **not** detect threats and has no attack tools; detection belongs to the SOC.

## Architecture
User -> Web Application -> Supabase Auth -> Application Event -> `security_events` -> Future CyberGuard SOC

| Real action | Event recorded |
|---|---|
| Supabase Auth rejects credentials | `FAILED_LOGIN` (MEDIUM, `/login`) |
| Supabase Auth accepts credentials | `LOGIN_SUCCESS` (LOW, `/login`) |
| Test Activity succeeds (database round trip `server_time()`) | `TEST_REQUEST` (LOW, `/test-activity`) |
| Logout clicked | `LOGOUT` (LOW, `/logout`), written just before `signOut()` because RLS needs the session |

**Source field:** a browser cannot safely know its public IP, so `source` is a random per-browser ID (`browser-xxxxxxxx`, stored in localStorage), or `LOCAL_CLIENT` if storage is blocked. Each attempt is a separate insert with its own timestamp, so 7 wrong passwords create 7 events.

**Failed logins** happen before authentication, so the anonymous role cannot insert directly. A restricted database function `log_failed_login` can only create `FAILED_LOGIN` rows and links them to a user if the email matches a profile (otherwise `user_id` is null). Anyone with your anon key could call it to add failed-login rows; this is accepted for a training lab.

## Technologies
HTML, CSS, vanilla JavaScript, Supabase Auth, Supabase PostgreSQL (supabase-js from CDN).

## Folder Structure
- `index.html` login page (+ "continue" notice if already signed in); `dashboard.html` user dashboard (redirects to login without a session); `about.html` short description
- `css/style.css` styles
- `js/supabase.js` URL/anon-key placeholders and client; `js/security.js` event helpers and utilities; `js/auth.js` login/logout; `js/dashboard.js` dashboard data and Test Activity
- `supabase/schema.sql` tables, trigger, RLS, functions

## Supabase Setup
Use a **NEW, SEPARATE Supabase project**, not one used by another project such as AttendX.
1. Create the new project.
2. Open **SQL Editor**.
3. Paste and run `supabase/schema.sql`.
4. **Authentication -> Providers**: make sure Email is enabled. For a simple demo, turn off "Confirm email" (or tick "Auto Confirm User" in the next step).
5. **Authentication -> Users -> Add user**: create the demo user (below).
6. **Project Settings -> API**: copy the Project URL.
7. Copy the **anon/public** key.
8. Put both into `js/supabase.js`. Never use the service-role key.

## Demo Account
Create `student@cyberguard.test` with password `CyberGuard123!` (Add user, Auto Confirm ticked). This password is not stored in the frontend code. If Supabase rejects it (for example leaked-password protection), use any stronger password you choose.

## Running Locally
Serve over HTTP: `python -m http.server 5500`, then open http://localhost:5500. Python is only a static file server here, not a backend.

## Testing
1. Open the login page.
2. Enter a wrong password.
3. Confirm "Invalid email or password."
4. In Supabase Table Editor -> `security_events`, look for the row.
5. Verify `FAILED_LOGIN` exists.
6. Log in with the correct credentials.
7. Verify `LOGIN_SUCCESS`.
8. Dashboard opens; opening `dashboard.html` while logged out redirects to login.
9. Click TEST ACTIVITY.
10. Verify `TEST_REQUEST`.
11. Click LOGOUT.
12. Verify `LOGOUT`.
13. Repeat failed logins 7 times.
14. Verify 7 separate `FAILED_LOGIN` rows with different timestamps.

Note: the dashboard shows only your own events (RLS), so failed attempts appear there when the email matches your account. Supabase Auth also has its own rate limits.

## Security (RLS)
Users can read only their own profile and events. Users can insert only their own `LOGIN_SUCCESS`/`LOGOUT`/`TEST_REQUEST` rows. There are no update or delete policies or privileges. No seed data is included.

## Future CyberGuard SOC
CyberGuard Test Server -> Security Events -> Supabase -> CyberGuard SOC -> Detection Engine -> Threat Alert -> Incident. Not built yet. Because RLS limits users to their own rows, the SOC will need its own access path (for example a separate read policy or a server-side key kept out of any frontend), to be designed in that project.
