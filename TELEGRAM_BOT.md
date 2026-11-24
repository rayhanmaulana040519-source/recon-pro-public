# Recon Pro Telegram control bot

This companion bot lets an approved user request a full Recon Pro pipeline from a private Telegram chat. It uses Python's standard library; there are no extra Python packages to install.

## What it does

- `/scan example.com` requests a scan, then shows inline Mulai scan/Batal buttons before it starts. The scan runs the active pipeline **and** the passive toolkit, so both reports are produced.
- `/passive example.com` runs only the passive OSINT + header toolkit and sends its findings.
- `/status` reports the current or most recent scan, plus the proxy pool size and rotation state.
- `/report [example.com]` sends the latest Telegram report for a configured target.
- `/findings [example.com]` sends the detailed findings from the Markdown report: what each bug is, its impact, the manual check and the fix.
- `/log [example.com]` sends the last scan log, the pipeline log tail and the per-stage results, so a failed stage is visible from the chat.
- `/tools` or `/doctor` lists which scanner tools are installed on the scan host.
- `/scope` lists the local scope allowlist; `/scope add domain.tld` and `/scope remove domain.tld` manage it from Telegram with inline confirmation buttons.
- The full pipeline also uses optional WhatWeb fingerprinting in single-request mode, capped at 100 in-scope URLs per scan.
- `/cancel` cancels a pending confirmation.
- `/stop` requests stopping your running scan; an inline confirmation button sends SIGTERM to its scan process group.

Only private chats from IDs listed in `TELEGRAM_ALLOWED_USERS` are accepted. Targets must exactly match a domain in the local allowlist, and the normal Recon Pro exclusion file still applies. Telegram text is never passed to a shell or used as scanner arguments other than the validated apex domain. A bot-launched scan uses the existing full pipeline, including its active checks.

## Requirements

- A machine that stays online while you use the bot. Telegram is only the remote control; scans run on this machine.
- Python 3.9 or newer (standard library only), Bash 4 or newer, and the Recon Pro tools. The existing pipeline can skip stages whose optional scanner tools are absent; `curl` and `jq` are recommended. WhatWeb is an optional addition and must be installed separately from its official project: https://github.com/urbanadventurer/WhatWeb
- A bot token created through Telegram's official BotFather.

## One-time setup

1. Create a bot with BotFather and keep its token private. Never put the token in this repository.
2. You do not need to edit the scope file manually. Once the bot is running, add each authorized apex domain in Telegram with `/scope add example.com` and tap the confirmation button. The bot stores the approved list in `~/recon_pro/state/scope.txt` with owner-only permissions (a list left at the older `~/.recon_pro_scope.txt` path is moved there automatically). Only add assets explicitly included by the bug-bounty program; an apex covers its discovered subdomains, subject to exclusions.
3. Store the bot token and the numeric Telegram user ID(s) allowed to operate it, once, with:

   ```bash
   bash recon.sh --telegram
   ```

   It asks for the token (hidden), the chat ID, and optionally the user IDs allowed
   to control the bot, then writes them to `~/recon_pro/state/recon_pro.conf` with
   owner-only permissions and sends a test message. The bot reads the same file, so
   no environment variables are needed.

   Environment variables still work and win over the file, if you prefer:
   `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ALLOWED_USERS` (comma-separated). Do not add
   group IDs. The bot intentionally ignores unapproved users and group chats.
4. From the project directory, start the bot and keep it running:

   ```bash
   python3 recon_pro_bot.py
   ```

   If your bot token was already configured in the recon config, that config is still used by the scan script for settings; the bot's private chat receives notifications for scans it starts. The config now lives at `~/recon_pro/state/recon_pro.conf`; a config left at the older `~/.recon_pro.conf` path is moved there automatically on the first start.

## Where everything is saved

All state and output lives under one folder, `~/recon_pro` (set `RECON_PRO_HOME` to move it):

| Path | Contents |
| --- | --- |
| `runs/<domain>/recon_<domain>_<timestamp>/` | one scan workspace |
| `runs/<domain>/latest` | link to the newest workspace |
| `reports/<domain>/latest-telegram_report.txt` | newest report, at a short path |
| `reports/<domain>/latest-report.md` | newest explained Markdown report |
| `bugbounty-toolkit/reports/<domain>-<timestamp>.md` | passive toolkit report (`/passive` or the end of `/scan`) |
| `state/recon_pro.conf` | scan settings |
| `state/exclusions.txt` | out-of-scope hostnames |
| `state/scope.txt` | Telegram-approved apex domains |
| `state/bot/` | bot lock, status and logs |

Files left at the older `~/.recon_pro.conf`, `~/.recon_pro_exclusions.txt`, `~/.recon_pro_scope.txt` and `~/.recon_pro_bot` paths are moved into the tree on the first start. `KEEP_RUNS=n` in settings keeps only the newest n runs per domain; the default is 0, which keeps every run.

## Use

Open the bot's private chat and send `/start`, then add an authorized apex with `/scope add example.com` and tap `Tambah`. Repeat for each program domain; use `/scope` to review the list. Request a scan with `/scan example.com`, then tap `Mulai scan` only if the target is in scope and you are authorized. Use `/status` while it runs, `/report` for the summary, `/findings` for the detailed per-bug explanation, `/log` when a stage looks wrong, and `/tools` to see what is installed. `/passive` runs only the passive toolkit (quick OSINT pass) without the active scanners. `/cancel` invalidates pending buttons.

The bot runs one scan at a time. It does not accept arbitrary shell commands, URLs, IPs, ports, custom payloads, or off-scope targets. It does not automate prompt-injection payloads, data extraction, or exploit chaining; the current Recon Pro pipeline is a general web/domain bug-bounty scanner, not a dedicated AI-agent vulnerability scanner.

## Troubleshooting: the bot does not answer

Check these in order:

1. **Private chat, not a group.** The bot ignores group chats entirely.
2. **Leading slash.** Send `/scan example.com`, not `scan example.com`. A bare
   command now gets a short hint instead of silence.
3. **Your numeric user ID** must be in `TELEGRAM_ALLOWED_USERS` (get it from
   `@userinfobot`). A wrong ID is ignored silently in chat, but the bot prints
   `Ignoring update: unapproved user (…)` on stderr.
4. **The bot must be running:** `python3 recon_pro_bot.py` and keep it alive
   (`tmux`, `screen`, or a systemd unit).
5. **Send `/start` to the bot once.** Telegram only lets a bot message a user who
   started it.
6. **`Another … bot process is already running (PID n)`** means an older instance
   still holds the lock. Stop it with `bash recon.sh --stop-bot`, or kill the PID
   directly. To list candidates reliably: `ps -eo pid,cmd | grep '[r]econ_pro_bot'`
   (the bracket keeps grep out of its own output).
7. **`HTTP 409 Conflict`** means another process is polling the same token. Stop
   it and disable any webhook, then restart.
7. **Nothing at all in the log?** The token is wrong or the process died; run the
   bot in the foreground to see the error.

## Operations and security

- Keep the scan host under your control. Approved Telegram users can manage the local scope file from the private chat; protect the bot token and restrict `TELEGRAM_ALLOWED_USERS` to trusted operators.
- The bot stores its lock, scan status, and logs under `~/recon_pro/state/bot` with owner-only permissions. Full scan output is stored inside the same folder tree: `~/recon_pro/runs/<domain>/recon_<domain>_<timestamp>/`, with per-target copy of the newest report in `~/recon_pro/reports/<domain>/`. A state folder left at the older `~/.recon_pro_bot` path is moved there automatically.
- Keep `~/recon_pro/state/exclusions.txt` current for program exclusions (an exclusions file left at the older `~/.recon_pro_exclusions.txt` path is moved there automatically). Stop the bot with Ctrl-C; a scan already started continues independently. Use `/stop` from the initiating private chat to request termination of its scan process group.
- If polling reports a Telegram `409 Conflict`, stop any other process using this bot token and disable any configured webhook before restarting.
- If the token is exposed, revoke it with BotFather and configure the replacement.
