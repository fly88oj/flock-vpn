# M8 Web UI browser real-machine checklist (the M8c screenshot round)

> §7-M8.9 "browser visual checks = the real-machine checklist": this file is the skeleton of the
> M8c review-approval browser checklist (landed in M8b; the "tested/screenshot" column of each
> item is filled in by M8c — attachment numbers and conclusions). How to access:
> `http://127.0.0.1:9800` (local machine) or `http://<VIP>:9800` (VPN segment; must have joined
> the network).
>
> Browser matrix: Chrome / Edge / Firefox (latest stable) × three viewport tiers (desktop ≥1200 /
> tablet 768–1024 / phone 360–430 — DevTools device emulation suffices).
>
> The automated substitute surface already done by M8b (for M8c to compare against; not a
> replacement for visual checks): container assertions W1–W7 (deploy/webui_assert.sh) + the local
> embedded-browser full-chain smoke (wasm login/account creation/password setting/three-tier
> layout scrollWidth checks).

## 1. Login and authentication

| # | Item | Action | Expected | Tested/screenshot |
|---|---|---|---|---|
| L1 | Login page centered at three tiers | open `#/login` at 360/768/1280 | card centered horizontally and vertically, no horizontal scrolling, form complete | |
| L2 | bootstrap connection state | stop the service, then refresh | "cannot reach the admin API" notice (not a blank page) | |
| L3 | Cluster identity display | open normally | "Cluster xxxxxxxx · Server xxxxxxxx" (first 8 characters) | |
| L4 | Login with the correct password | full wasm OPAQUE flow | enters the dashboard; sidebar shows username/role/origin | |
| L5 | Wrong password | submit a wrong password | "Invalid username or password."; the button spinner recovers | |
| L6 | Disabled account | admin disables the account, then that account logs in | "This account has been disabled. Contact your administrator." | |
| L7 | 429 rate limiting | keep making wrong attempts until limited | "Too many attempts. Retry in N seconds." with a countdown | |
| L8 | anchor rejection (wrong server) | access via a wrong proxy/port | "Server identity verification failed…" (the wasm -3 surface) | |
| L9 | Set-password page | account-creation token + the new password twice | success notice → go to login; a bad token gives "The bootstrap token is invalid or already used." | |
| L10 | Token replay | set the password a second time with the same token | the same bad_token copy (one-time semantics) | |
| L11 | Logout | sidebar "log out" | back to the login page; the back button does not restore the session | |

## 2. Dashboard

| # | Item | Action | Expected | Tested/screenshot |
|---|---|---|---|---|
| D1 | Cluster card | look on login | cluster_id/epoch/sync mode (single or raft) | |
| D2 | Server cards (multi-primary) | log in on the two-server topology | per server: node/VIP/endpoint/leader badge/epoch/online dot | |
| D3 | Summary card | look | total devices/active/online/account count/summed tx-rx rates | |
| D4 | Self info | look | server_id (first 8 characters) + uptime | |
| D5 | Traffic curves | select a device VIP | the uPlot dual series (sent/received) appears and advances with the 60s polling | |
| D6 | Curve timezone | compare with the system clock | x-axis ticks are local time (no UTC offset) | |
| D7 | Curve tooltip | desktop hover / phone touch | time point + both series' rates; on mobile it does not cover the curve | |
| D8 | Curve responsiveness | drag the window width | chart width follows the container (no misalignment on resize) | |
| D9 | Empty-series state | look right after a service restart | "No traffic samples for this device yet…" empty-state copy (not a blank area) | |

## 3. Devices

| # | Item | Action | Expected | Tested/screenshot |
|---|---|---|---|---|
| P1 | Full-status table | look (desktop) | VIP/hostname/account/type/status/last active/traffic/actions — all columns | |
| P2 | Status badges | with disabled/revoked devices present | active (green)/disabled (yellow)/revoked (red)/expired (grey) | |
| P3 | Online dot | with online devices | green dot + "online" | |
| P4 | Revoke confirmation modal | click "revoke" | a double-confirmation modal (terminal-state warning); Esc/cancel backs out | |
| P5 | Revoke execution | confirm | success toast (with epoch); the in-table status turns "revoked" | |
| P6 | Disable/enable | execute in turn | toast + status badge switches; the action buttons appear/hide per status | |
| P7 | Force disconnect | kick an online device | the confirmation modal copy carries the "best-effort disconnect… not a ban" semantics | |
| P8 | Phone-tier cards | 360–430px viewport | the table degrades into a card list; VIP/status/actions fully retained | |
| P9 | Touch targets | tap actions in the phone tier | button height ≥44px, no horizontal scrolling | |
| P10 | Non-admin | bob logs in on the devices page | list visible, no actions column (the admin-API 403 surface not triggered) | |

## 4. Accounts (admin)

| # | Item | Action | Expected | Tested/screenshot |
|---|---|---|---|---|
| U1 | Users table | look | username/role/status/password/device count/actions | |
| U2 | Create account | submit a new username | the token modal shown once (32hex) + a copy button + guidance copy | |
| U3 | Token copy | click "copy" | the clipboard holds the full token; the button turns "copied" | |
| U4 | Token exactly once | close the modal and reopen | nowhere to retrieve the token again (no token column in the table) | |
| U5 | Guidance modal entry | click "open the set-password page on this machine" | jumps to `#/set-password` with the username prefilled | |
| U6 | Disable/enable | execute in turn | badge switches; after disabling, that user's Web login is rejected (linked with L6) | |
| U7 | Reset password | for a user who has a password | new-token modal; the old password fails login immediately | |
| U8 | Grant/revoke admin | execute in turn | role badge switches; self-demotion rejected (cannot_demote_self copy) | |
| U9 | Username constraints | enter `bad user!` and submit | rejected by the frontend/server (legal-charset hint) | |

## 5. Audit and settings

| # | Item | Action | Expected | Tested/screenshot |
|---|---|---|---|---|
| A1 | Audit table | admin view | within 200 rows, new→old; time/operator/action/target/origin/result | |
| A2 | Action-vocabulary localization | view | all 11 vocabulary items localized (log in/log out/create account/…/force disconnect) | |
| A3 | denied/error rows | trigger one 403 attempt | the corresponding denied row is listed | |
| A4 | Non-admin direct hit | bob hand-types `#/audit` | the "no permission" page (the 403 rendered by the frontend) | |
| A5 | Settings summary | view | read-only key-values (endpoint/mode/ticket TTL/retention days/session cap/webui port and TTL); no key-like fields | |

## 6. Responsive and accessibility cross-cutting items

| # | Item | Action | Expected | Tested/screenshot |
|---|---|---|---|---|
| R1 | Three-tier navigation | <1200 / <768 | top bar + hamburger drawer; drawer closes on overlay click/Esc | |
| R2 | No horizontal scrolling | walk every page at the three tiers | no page has a horizontal scrollbar (DevTools ruler 0) | |
| R3 | Functional completeness | walk every function in the phone tier | all actions reachable (login/account creation/token/device actions/audit); no "desktop only" | |
| R4 | Dark-theme consistency | across the three browsers | palette/radius/shadows consistent; the system font stack renders normally | |
| R5 | Reduced-motion preference | enable at the OS level and refresh | transitions/animations nearly instantaneous (prefers-reduced-motion) | |
| R6 | Keyboard reachability | Tab through the login page | focus ring visible, Enter submits, Esc closes modals | |

## 7. Performance sampling (M8c quantitative items)

- Time from the login button → entering the dashboard (argon2 on the main thread is on the order
  of ~100ms — a known v1 trade-off).
- CPU/memory sampling of the dashboard's 60s polling (the 120-point uPlot redraw is
  imperceptible).
- First-load resources: index.html + app/i18n/styles + vendor (alpine 44.8KB / uplot 39.4KB /
  flock_pake.js 8KB / flock_pake.wasm ~845KB — acceptable on LAN/VPN segments; recorded as-is).
