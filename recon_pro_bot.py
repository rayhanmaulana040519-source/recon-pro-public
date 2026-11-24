#!/usr/bin/env python3
"""Telegram control bot for the authorized Recon Pro bug-bounty pipeline.

Uses only Python's standard library. It never accepts shell commands or scanner
arguments from Telegram; scan targets must exactly match a locally configured
scope entry and sensitive actions require a short-lived inline confirmation button.
"""

import fcntl
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

API_BASE = "https://api.telegram.org/bot{}"
MAX_MESSAGE = 3500
CONFIRM_TTL = 180
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

# Commands the bot understands. Used to spot a command typed without the leading
# slash, which otherwise looks like idle chat and gets no reply at all.
KNOWN_COMMANDS = {
    "start", "help",
    "scan", "passive", "osint",
    "scope", "stop", "cancel", "status",
    "report", "findings", "finding", "bugs",
    "log", "logs",
    "doctor", "tools",
}


class BotError(Exception):
    pass


def normalize_domain(value):
    domain = value.strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or "://" in domain or "/" in domain:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or not all(DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return domain


def allowed_user_ids():
    raw = os.environ.get("TELEGRAM_ALLOWED_USERS", "")
    if not raw.strip():
        # Fallback: whatever `bash recon.sh --telegram` stored in the config.
        raw = config_value("TELEGRAM_ALLOWED_USERS")
    ids = set()
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        if not re.fullmatch(r"[1-9][0-9]*", value):
            raise BotError("TELEGRAM_ALLOWED_USERS must be comma-separated numeric Telegram user IDs.")
        ids.add(int(value))
    if not ids:
        raise BotError(
            "Set TELEGRAM_ALLOWED_USERS, or store it with: bash recon.sh --telegram"
        )
    return ids


def env_path(name, default):
    return Path(os.path.expanduser(os.environ.get(name, str(default)))).resolve()


def recon_home():
    """The single folder the scan script writes everything into."""
    configured = os.environ.get("RECON_PRO_HOME", "").strip()
    if configured:
        return Path(os.path.expanduser(configured)).resolve()
    return (Path.home() / "recon_pro").resolve()


def config_value(key):
    """Read ``KEY|value`` from the pipeline config in recon_home/state.

    Lets the bot run without exporting anything: whatever ``recon.sh --telegram``
    stored is reused here.
    """
    path = recon_home() / "state" / "recon_pro.conf"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        if "|" in line:
            name, value = line.split("|", 1)
        elif "=" in line:
            name, value = line.split("=", 1)
        else:
            continue
        if name.strip() == key:
            return value.strip().strip('"')
    return ""


def existing_or_new(new_path, legacy_path):
    """Prefers the new location, falls back to where older versions kept it."""
    new_path = Path(new_path)
    if new_path.exists():
        return new_path
    legacy_path = Path(legacy_path)
    if legacy_path.exists():
        return legacy_path
    return new_path


def timestamp(value):
    try:
        return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (TypeError, ValueError, OSError):
        return "unknown"


class ReconTelegramBot:
    def __init__(self):
        self.token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip() or config_value("TELEGRAM_TOKEN")
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", self.token):
            raise BotError(
                "Set TELEGRAM_BOT_TOKEN, or store the token once with: bash recon.sh --telegram"
            )

        self.users = allowed_user_ids()
        self.script = env_path("RECON_PRO_SCRIPT", Path(__file__).with_name("recon_pro.sh"))
        if not self.script.is_file():
            raise BotError("Recon Pro script not found. Set RECON_PRO_SCRIPT to its path.")

        self.bash = os.environ.get("RECON_PRO_BASH", "bash")
        root = recon_home()
        self.scope_file = env_path(
            "BUGBOUNTY_SCOPE_FILE",
            existing_or_new(root / "state" / "scope.txt", Path.home() / ".recon_pro_scope.txt"),
        )
        self.state_dir = env_path(
            "RECON_PRO_BOT_STATE",
            existing_or_new(root / "state" / "bot", Path.home() / ".recon_pro_bot"),
        )
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self.state_file = self.state_dir / "state.json"
        self.offset_file = self.state_dir / "update_offset"
        self.pending_buttons = {}
        self.process = None
        self._ignored_noted = set()
        self.offset = self._load_offset()

        lock_path = self.state_dir / "bot.lock"
        self.lock_handle = lock_path.open("a+")
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            holder = ""
            try:
                self.lock_handle.seek(0)
                holder = self.lock_handle.read().strip()
            except OSError:
                holder = ""
            detail = " (PID {})".format(holder) if holder else ""
            raise BotError(
                "Another Recon Pro Telegram bot process is already running{}.\n"
                "Stop it with: bash recon.sh --stop-bot\n"
                "If that does not work, find it with: ps -eo pid,cmd | grep '[r]econ_pro_bot.py'".format(detail)
            )
        # Record the owner so the next start can name the process that holds it.
        try:
            self.lock_handle.seek(0)
            self.lock_handle.truncate()
            self.lock_handle.write(str(os.getpid()))
            self.lock_handle.flush()
        except OSError:
            pass

    def api_call(self, method, data=None, timeout=40):
        url = API_BASE.format(self.token) + "/" + method
        body = urllib.parse.urlencode(data or {}).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read(300).decode("utf-8", errors="replace")
            raise BotError("Telegram API HTTP {}: {}".format(error.code, detail))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            raise BotError("Telegram request failed: {}".format(getattr(error, "reason", str(error))))
        if not isinstance(result, dict) or not result.get("ok"):
            raise BotError("Telegram API returned an unsuccessful response.")
        return result.get("result")

    def send(self, chat_id, text):
        text = str(text)
        if len(text) > MAX_MESSAGE:
            text = text[: MAX_MESSAGE - 20] + "\n[message truncated]"
        self.api_call("sendMessage", {"chat_id": str(chat_id), "text": text}, timeout=20)

    def send_with_buttons(self, chat_id, text, token, confirm_label):
        keyboard = {
            "inline_keyboard": [[
                {"text": confirm_label, "callback_data": "ok:" + token},
                {"text": "Batal", "callback_data": "cancel:" + token},
            ]]
        }
        return self.api_call(
            "sendMessage",
            {
                "chat_id": str(chat_id),
                "text": str(text),
                "reply_markup": json.dumps(keyboard, ensure_ascii=False),
            },
            timeout=20,
        )

    def ask_confirmation(self, chat_id, user_id, action, details, text, confirm_label):
        for token, pending in list(self.pending_buttons.items()):
            if pending.get("chat_id") == int(chat_id):
                self.pending_buttons.pop(token, None)
                self.clear_buttons(chat_id, pending.get("message_id"))
        token = secrets.token_urlsafe(12)
        self.pending_buttons[token] = {
            "chat_id": int(chat_id),
            "user_id": int(user_id),
            "action": action,
            "details": details,
            "expires": time.time() + CONFIRM_TTL,
        }
        try:
            sent = self.send_with_buttons(chat_id, text, token, confirm_label)
            if isinstance(sent, dict):
                self.pending_buttons[token]["message_id"] = sent.get("message_id")
        except BotError:
            self.pending_buttons.pop(token, None)
            raise

    def answer_callback(self, callback_id, text):
        if not callback_id:
            return
        try:
            self.api_call(
                "answerCallbackQuery",
                {"callback_query_id": callback_id, "text": text[:180]},
                timeout=20,
            )
        except BotError as error:
            print("Telegram callback acknowledgement failed: {}".format(error), file=sys.stderr)

    def clear_buttons(self, chat_id, message_id):
        if not chat_id or not message_id:
            return
        try:
            self.api_call(
                "editMessageReplyMarkup",
                {
                    "chat_id": str(chat_id),
                    "message_id": str(message_id),
                    "reply_markup": json.dumps({"inline_keyboard": []}),
                },
                timeout=20,
            )
        except BotError:
            pass

    def execute_confirmation(self, pending):
        chat_id = pending["chat_id"]
        user_id = pending["user_id"]
        action = pending["action"]
        details = pending.get("details", {})
        try:
            if action == "scan":
                domain = details["domain"]
                if not self.scope_allows(domain):
                    self.send(chat_id, "Scope changed; {} is no longer allowed, so no scan started.".format(domain))
                    return
                self.start_scan(chat_id, user_id, domain)
                return
            if action in ("scope_add", "scope_remove"):
                operation = action[len("scope_"):]
                domain = details["domain"]
                self.update_scope(operation, domain)
                result = "Added" if operation == "add" else "Removed"
                self.send(chat_id, "{} {} in the scope list. Use /scope to review it.".format(result, domain))
                return
            if action == "stop":
                pid = int(details["pid"])
                active = self.active_scan()
                if not active or self.process is None or self.process.pid != pid:
                    self.send(chat_id, "That scan is no longer running in this bot session.")
                    return
                if int(active.get("user_id", 0)) != user_id:
                    self.send(chat_id, "Only the user who started this scan can stop it.")
                    return
                os.killpg(pid, signal.SIGTERM)
                self.send(chat_id, "Stop signal sent to the scan and its child tools. Use /status to verify it stopped.")
                return
            self.send(chat_id, "Unknown confirmation action; nothing was run.")
        except ProcessLookupError:
            self.send(chat_id, "The scan process already ended.")
        except (OSError, BotError, KeyError, ValueError) as error:
            self.send(chat_id, "Action could not be completed: {}".format(error))

    def handle_callback(self, callback):
        callback_id = callback.get("id")
        message = callback.get("message") or {}
        chat = message.get("chat") or {}
        sender = callback.get("from") or {}
        try:
            user_id = int(sender.get("id", 0))
            chat_id = int(chat.get("id", 0))
        except (TypeError, ValueError):
            self.answer_callback(callback_id, "Invalid request")
            return
        if chat.get("type") != "private" or user_id not in self.users or chat_id != user_id:
            self.answer_callback(callback_id, "Not authorized")
            return

        match = re.fullmatch(r"(ok|cancel):([A-Za-z0-9_-]+)", callback.get("data", ""))
        if not match:
            self.answer_callback(callback_id, "Invalid button")
            return
        choice, token = match.groups()
        pending = self.pending_buttons.get(token)
        if not pending or pending.get("chat_id") != chat_id or pending.get("user_id") != user_id:
            self.answer_callback(callback_id, "This button has expired")
            self.clear_buttons(chat_id, message.get("message_id"))
            return
        if time.time() > pending["expires"]:
            self.pending_buttons.pop(token, None)
            self.answer_callback(callback_id, "This button has expired")
            self.clear_buttons(chat_id, message.get("message_id"))
            return

        self.pending_buttons.pop(token, None)
        self.answer_callback(callback_id, "Cancelled" if choice == "cancel" else "Confirmed")
        self.clear_buttons(chat_id, message.get("message_id"))
        if choice == "cancel":
            self.send(chat_id, "Action cancelled.")
            return
        self.execute_confirmation(pending)

    def handle_update(self, update):
        callback = update.get("callback_query") if isinstance(update, dict) else None
        if isinstance(callback, dict):
            self.handle_callback(callback)
        else:
            self.command(update)

    def send_chunked(self, chat_id, text):
        chunks = []
        current = ""
        for line in text.splitlines() or [text]:
            if len(line) > MAX_MESSAGE - 100:
                line = line[: MAX_MESSAGE - 104] + " ..."
            if current and len(current) + len(line) + 1 > MAX_MESSAGE - 80:
                chunks.append(current)
                current = ""
            current += ("\n" if current else "") + line
        if current:
            chunks.append(current)
        if not chunks:
            chunks = ["No report text available."]
        for index, chunk in enumerate(chunks[:8], 1):
            suffix = "" if len(chunks) == 1 else " (part {}/{})".format(index, min(len(chunks), 8))
            self.send(chat_id, chunk + suffix)
        if len(chunks) > 8:
            self.send(chat_id, "Remaining report text omitted; read the full report on the scan host.")

    def _load_offset(self):
        try:
            value = int(self.offset_file.read_text(encoding="ascii").strip())
            return max(0, value)
        except (OSError, ValueError):
            return 0

    def _save_offset(self):
        temporary = self.offset_file.with_suffix(".tmp")
        temporary.write_text(str(self.offset), encoding="ascii")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.offset_file)

    def _read_state(self):
        try:
            state = json.loads(self.state_file.read_text(encoding="utf-8"))
            return state if isinstance(state, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_state(self, state):
        temporary = self.state_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.state_file)

    @staticmethod
    def _pid_alive(pid):
        try:
            pid = int(pid)
            if pid <= 1:
                return False
            os.kill(pid, 0)
            return True
        except (TypeError, ValueError, ProcessLookupError):
            return False
        except PermissionError:
            return True

    def _finish_scan(self, return_code, notify=True):
        state = self._read_state()
        state["status"] = "completed" if return_code == 0 else "failed"
        state["exit_code"] = int(return_code)
        state["finished_at"] = time.time()
        self._write_state(state)
        chat_id = state.get("chat_id")
        domain = state.get("domain", "unknown")
        log_path = state.get("log", "")
        self.process = None
        if notify and chat_id:
            message = "Scan {} {} (exit {}). Log: {}".format(
                "completed for" if return_code == 0 else "failed for", domain, return_code, log_path
            )
            try:
                self.send(chat_id, message)
            except BotError as error:
                print("Telegram completion message failed: {}".format(error), file=sys.stderr)

    def refresh_scan_state(self):
        if self.process is not None:
            return_code = self.process.poll()
            if return_code is not None:
                self._finish_scan(return_code)
            return

        state = self._read_state()
        if state.get("status") == "running" and not self._pid_alive(state.get("pid", 0)):
            state["status"] = "finished_after_bot_restart"
            state["finished_at"] = time.time()
            self._write_state(state)
            if state.get("chat_id"):
                try:
                    self.send(state["chat_id"], "Scan process ended while the bot was offline. Check the saved log: {}".format(state.get("log", "")))
                except BotError:
                    pass

    def active_scan(self):
        self.refresh_scan_state()
        state = self._read_state()
        if state.get("status") == "running" and self._pid_alive(state.get("pid", 0)):
            return state
        return None

    def scope_domains(self):
        if not self.scope_file.exists():
            return []
        domains = []
        invalid = []
        for number, raw in enumerate(self.scope_file.read_text(encoding="utf-8").splitlines(), 1):
            value = raw.split("#", 1)[0].strip().lower()
            if not value:
                continue
            if value.startswith("*."):
                value = value[2:]
            domain = normalize_domain(value)
            if domain is None:
                invalid.append(str(number))
                continue
            domains.append(domain)
        if invalid:
            raise BotError("Invalid domain(s) in {} on line(s): {}. Use one apex domain per line.".format(self.scope_file, ", ".join(invalid)))
        return sorted(set(domains))

    def scope_allows(self, domain):
        return domain in self.scope_domains()

    def update_scope(self, action, domain):
        domains = self.scope_domains()
        exists = domain in domains
        if action == "add" and exists:
            raise BotError("{} is already in the scope allowlist.".format(domain))
        if action == "remove" and not exists:
            raise BotError("{} is not in the scope allowlist.".format(domain))
        if action not in ("add", "remove"):
            raise BotError("Unsupported scope operation.")

        self.scope_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lines = self.scope_file.read_text(encoding="utf-8").splitlines() if self.scope_file.exists() else []
        if action == "add":
            lines.append(domain)
        else:
            kept = []
            removed = False
            for raw in lines:
                value = raw.split("#", 1)[0].strip().lower()
                if value.startswith("*."):
                    value = value[2:]
                if normalize_domain(value) == domain:
                    removed = True
                else:
                    kept.append(raw)
            if not removed:
                raise BotError("{} could not be removed from the scope file.".format(domain))
            lines = kept

        content = "\n".join(lines)
        if content and not content.endswith("\n"):
            content += "\n"
        descriptor, temporary = tempfile.mkstemp(prefix=".recon-pro-scope-", dir=str(self.scope_file.parent))
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(content)
            os.replace(temporary, self.scope_file)
            os.chmod(self.scope_file, 0o600)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return self.scope_domains()

    def config_file(self):
        """The config in the shared folder, or the hidden file older versions used."""
        return existing_or_new(
            recon_home() / "state" / "recon_pro.conf",
            Path.home() / ".recon_pro.conf",
        )

    def reports_dir(self):
        return recon_home() / "reports"

    def output_base(self):
        """The runs folder: <root>/runs unless the config points somewhere else."""
        base = recon_home() / "runs"
        try:
            for raw in self.config_file().read_text(encoding="utf-8").splitlines():
                if raw.startswith("OUTPUT_BASE|"):
                    value = raw.split("|", 1)[1]
                elif raw.startswith("OUTPUT_BASE="):
                    value = raw.split("=", 1)[1].strip().strip('"')
                else:
                    continue
                if value:
                    base = Path(os.path.expanduser(value))
        except OSError:
            pass
        if not base.is_absolute():
            base = recon_home() / base
        return base

    def _read_report(self, path):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return path, None
        return path, text[:24000]

    def latest_report(self, domain):
        """Newest report for a domain: the published copy, a run, then the old layout."""
        published = self.reports_dir() / domain
        for name in ("latest-telegram_report.txt", "latest-bugs_found.txt"):
            path = published / name
            if path.is_file():
                return self._read_report(path)

        telegram_patterns = (
            "{}/recon_*/final/telegram_report.txt".format(domain),
            "*/{}/recon_*/final/telegram_report.txt".format(domain),
            "recon_{}_*/final/telegram_report.txt".format(domain),
        )
        bugs_patterns = (
            "{}/recon_*/final/bugs_found.txt".format(domain),
            "*/{}/recon_*/final/bugs_found.txt".format(domain),
        )

        base = self.output_base()
        if not base.is_dir():
            return None, None
        for patterns in (telegram_patterns, bugs_patterns):
            for pattern in patterns:
                candidates = [path for path in base.glob(pattern) if path.is_file()]
                if candidates:
                    report = max(candidates, key=lambda path: path.stat().st_mtime)
                    return self._read_report(report)

        return None, None

    # -- read-only helpers ----------------------------------------------------
    def _read_text(self, path, limit=40000):
        """Read a text file, returning ``None`` when it cannot be read."""
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
        except OSError:
            return None

    def markdown_report(self, domain):
        """Return ``(path, text)`` of the newest explained report.md."""
        candidates = [
            self.reports_dir() / domain / "latest-report.md",
            self.output_base() / domain / "latest" / "final" / "report.md",
        ]
        for path in candidates:
            if path.is_file():
                text = self._read_text(path)
                if text is not None:
                    return path, text
        return None, None

    @staticmethod
    def markdown_section(text, heading):
        """Return the body of the ``## <heading>`` section of a Markdown report."""
        marker = "## " + heading
        collected = []
        inside = False
        for line in text.splitlines():
            if line.strip() == marker:
                inside = True
                continue
            if inside and line.startswith("## "):
                break
            if inside:
                collected.append(line)
        return "\n".join(collected).strip()

    def scan_log_path(self, domain):
        """Newest bot-side log of a scan started from this chat."""
        candidates = [path for path in self.state_dir.glob("scan_{}_*.log".format(domain)) if path.is_file()]
        if not candidates:
            return None
        return max(candidates, key=lambda path: path.stat().st_mtime)

    def pipeline_log_path(self, domain):
        """Pipeline log of the newest run for a domain."""
        path = self.output_base() / domain / "latest" / "logs" / "pipeline.log"
        return path if path.is_file() else None

    def stage_summary(self, domain):
        """One line per stage: name, result, detail."""
        path = self.output_base() / domain / "latest" / "logs" / "stages.tsv"
        if not path.is_file():
            return ""
        text = self._read_text(path, 8000)
        if not text:
            return ""
        rows = []
        for line in text.splitlines():
            if not line.strip():
                continue
            rows.append(" | ".join(part.strip() for part in line.split("\t")))
        return "\n".join(rows)

    def proxy_status(self):
        """Summarise the rotating proxy pool from the config and the proxy file."""
        settings = {}
        try:
            for raw in self.config_file().read_text(encoding="utf-8").splitlines():
                if "|" in raw:
                    key, value = raw.split("|", 1)
                elif "=" in raw:
                    key, value = raw.split("=", 1)
                else:
                    continue
                settings[key.strip()] = value.strip().strip('"')
        except OSError:
            pass

        proxy_path = settings.get("PROXY_FILE") or "state/proxies.txt"
        proxy_file = Path(os.path.expanduser(proxy_path))
        if not proxy_file.is_absolute():
            proxy_file = recon_home() / proxy_file

        entries = 0
        try:
            for line in proxy_file.read_text(encoding="utf-8").splitlines():
                value = line.split("#", 1)[0].strip()
                if value:
                    entries += 1
        except OSError:
            pass

        return {
            "entries": entries,
            "rotate": settings.get("PROXY_ROTATE", "1") != "0",
            "required": settings.get("PROXY_REQUIRED", "0") == "1",
            "file": str(proxy_file),
        }

    def _report_domain(self, argument):
        """Domain for a read-only command, honouring the allowlist."""
        domain = normalize_domain(argument) if argument else None
        if not domain:
            state = self._read_state() or {}
            domain = state.get("domain")
        if not domain:
            return None
        try:
            if not self.scope_allows(domain):
                return None
        except (OSError, BotError):
            return None
        return domain

    def start_scan(self, chat_id, user_id, domain):
        active = self.active_scan()
        if active:
            self.send(chat_id, "A scan is already running for {} (PID {}). Wait for it to finish before starting another.".format(active.get("domain", "unknown"), active.get("pid", "?")))
            return
        if not self.scope_allows(domain):
            self.send(chat_id, "{} is not an exact match in the local bug-bounty scope file. No scan started.".format(domain))
            return

        log_path = self.state_dir / "scan_{}_{}.log".format(domain, int(time.time()))
        child_env = os.environ.copy()
        child_env["TELEGRAM_BOT_TOKEN"] = self.token
        child_env["TELEGRAM_CHAT_ID"] = str(chat_id)
        child_env["RECON_PRO_BOT_WORKER"] = "1"
        try:
            # recon.sh runs the active pipeline and then the passive toolkit, so a
            # scan requested from chat produces both reports. --no-setup keeps the
            # bot from installing packages mid-scan; --yes skips the interactive
            # authorization prompt (the chat button is the confirmation).
            wrapper = self.script.with_name("recon.sh")
            if wrapper.is_file():
                command = [self.bash, str(wrapper), "--no-setup", "--yes", domain]
            else:
                command = [self.bash, str(self.script), "--yes", domain]
            with log_path.open("ab") as log_file:
                process = subprocess.Popen(
                    command,
                    cwd=str(self.script.parent),
                    env=child_env,
                    stdin=subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
        except OSError as error:
            self.send(chat_id, "Could not start the scan: {}".format(error))
            return

        self.process = process
        state = {
            "status": "running",
            "domain": domain,
            "pid": process.pid,
            "chat_id": int(chat_id),
            "user_id": int(user_id),
            "started_at": time.time(),
            "log": str(log_path),
        }
        try:
            self._write_state(state)
        except OSError as error:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
            self.process = None
            raise BotError("Could not save scan state; the newly started scan was stopped: {}".format(error))
        try:
            self.send(chat_id, "Scan started for {}. Only the configured scope and exclusions are used. Use /status to check progress.".format(domain))
        except BotError as error:
            print("Scan started, but its Telegram acknowledgement failed: {}".format(error), file=sys.stderr)

    def _note_ignored(self, reason, identifier):
        """Log an ignored update once per sender, to stderr only.

        The bot stays silent towards unapproved users and group chats on purpose,
        but the operator still needs to see that a message arrived and was
        dropped, otherwise it looks like the bot is dead.
        """
        key = "{}:{}".format(reason, identifier)
        if key in self._ignored_noted:
            return
        self._ignored_noted.add(key)
        print("Ignoring update: {} ({}).".format(reason, identifier), file=sys.stderr, flush=True)

    def command(self, update):
        message = update.get("message") if isinstance(update, dict) else None
        if not isinstance(message, dict):
            return
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        if chat.get("type") != "private":
            self._note_ignored("group chat", chat.get("id"))
            return
        try:
            user_id = int(sender.get("id", 0))
            chat_id = int(chat.get("id", 0))
        except (TypeError, ValueError):
            return
        if user_id not in self.users or chat_id != user_id:
            self._note_ignored("unapproved user", user_id)
            return

        text = (message.get("text") or "").strip()
        match = re.match(r"^/([A-Za-z0-9_]+)(?:@[A-Za-z0-9_]+)?(?:\s+(.*))?$", text, re.S)
        if not match:
            # A command typed without the leading slash is the most common reason
            # someone thinks the bot is dead, so answer instead of staying silent.
            first = text.split(maxsplit=1)[0].lower() if text else ""
            if first in KNOWN_COMMANDS:
                self.send(chat_id, "Perintah harus diawali garis miring.\n\nContoh: /scan example.com\nDaftar perintah: /help")
            return
        command = match.group(1).lower()
        argument = (match.group(2) or "").strip()

        if command in ("start", "help"):
            self.send(chat_id, "Recon Pro bug-bounty bot\n\n/scan domain.tld — request a scan for an allowlisted apex domain (active pipeline + passive toolkit)\n/passive domain.tld — run only the passive OSINT + header toolkit\n/scope — list approved apex domains\n/scope add domain.tld — request adding an approved domain\n/scope remove domain.tld — request removing a domain\n/stop — request stopping your running scan\n/cancel — cancel pending button confirmations\n/status — show scan status, progress and the proxy pool\n/report [domain.tld] — send the latest report for an allowlisted domain\n/findings [domain.tld] — send the detailed findings (what it is, impact, how to check, fix)\n/log [domain.tld] — send the last scan log, pipeline log and per-stage errors\n/doctor or /tools — check which scanner tools are installed\n\nTanpa /passive pun, /scan sudah menjalankan toolkit pasif di akhir. Perintah harus diawali garis miring (contoh: /scan example.com), bukan scan saja. Tap the action button (for example, Mulai scan or Tambah) or Batal on the bot's message. Buttons expire after 3 minutes. Private chat and an approved Telegram user ID are required; arbitrary shell commands are never accepted.")
            return

        if command == "scope":
            parts = argument.split()
            if not parts or (len(parts) == 1 and parts[0].lower() == "list"):
                try:
                    domains = self.scope_domains()
                except (OSError, BotError) as error:
                    self.send(chat_id, str(error))
                    return
                if not domains:
                    self.send(chat_id, "Scope list is empty. Add an authorized apex with /scope add example.com, then tap the confirmation button.")
                else:
                    self.send(chat_id, "Allowed apex domains:\n" + "\n".join("• " + domain for domain in domains) + "\n\nAdd: /scope add example.com\nRemove: /scope remove example.com")
                return

            action = parts[0].lower()
            if len(parts) != 2 or action not in ("add", "remove"):
                self.send(chat_id, "Usage: /scope list | /scope add example.com | /scope remove example.com")
                return
            target = parts[1]
            if target.startswith("*."):
                target = target[2:]
            domain = normalize_domain(target)
            if not domain:
                self.send(chat_id, "Use an apex domain only, such as /scope add example.com (no URL, IP, port, path, or CIDR).")
                return
            try:
                domains = self.scope_domains()
            except (OSError, BotError) as error:
                self.send(chat_id, str(error))
                return
            if action == "add" and domain in domains:
                self.send(chat_id, "{} is already in the scope list.".format(domain))
                return
            if action == "remove" and domain not in domains:
                self.send(chat_id, "{} is not in the scope list.".format(domain))
                return
            self.ask_confirmation(
                chat_id,
                user_id,
                "scope_" + action,
                {"domain": domain},
                "{} {} in the scope list? Only add domains explicitly authorized by the bug-bounty program.".format(action.title(), domain),
                "Tambah" if action == "add" else "Hapus",
            )
            return

        if command == "scan":
            domain = normalize_domain(argument)
            if not domain:
                self.send(chat_id, "Usage: /scan example.com (apex domain only; no scheme, path, port, or wildcard).")
                return
            try:
                if not self.scope_allows(domain):
                    self.send(chat_id, "{} is not in the local exact-match scope allowlist. No scan started.".format(domain))
                    return
            except (OSError, BotError) as error:
                self.send(chat_id, str(error))
                return
            self.ask_confirmation(
                chat_id,
                user_id,
                "scan",
                {"domain": domain},
                "Start the configured Recon Pro pipeline for {}? It includes active checks; only proceed if you are authorized to test this exact scope.".format(domain),
                "Mulai scan",
            )
            return

        if command == "cancel":
            cancelled = False
            for token, pending in list(self.pending_buttons.items()):
                if pending.get("chat_id") == chat_id:
                    self.pending_buttons.pop(token, None)
                    self.clear_buttons(chat_id, pending.get("message_id"))
                    cancelled = True
            if cancelled:
                self.send(chat_id, "Pending action cancelled.")
            else:
                self.send(chat_id, "There is no pending action. Stop a running scan with /stop.")
            return

        if command == "stop":
            active = self.active_scan()
            if not active:
                self.send(chat_id, "There is no running scan to stop.")
                return
            if int(active.get("user_id", 0)) != user_id:
                self.send(chat_id, "Only the user who started this scan can stop it.")
                return
            if self.process is None or self.process.pid != int(active.get("pid", 0)):
                self.send(chat_id, "This scan belongs to a previous bot session; stop it directly on the scan host.")
                return
            self.ask_confirmation(
                chat_id,
                user_id,
                "stop",
                {"pid": self.process.pid},
                "Stop the running scan for {} and its child scanner processes?".format(active.get("domain", "unknown")),
                "Stop scan",
            )
            return

        if command == "status":
            proxy = self.proxy_status()
            proxy_note = "proxy: {} entr(y), rotation {}".format(
                proxy["entries"], "on" if proxy["rotate"] else "off"
            )
            if proxy["required"] and proxy["entries"] == 0:
                proxy_note += " (REQUIRED but the list is empty)"
            active = self.active_scan()
            if active:
                self.send(chat_id, "RUNNING: {}\nStarted: {}\nPID: {}\n{}\nLog: {}".format(
                    active.get("domain", "?"),
                    timestamp(active.get("started_at")),
                    active.get("pid", "?"),
                    proxy_note,
                    active.get("log", ""),
                ))
            else:
                state = self._read_state()
                if not state:
                    self.send(chat_id, "No scan has been started by this bot yet.\n{}".format(proxy_note))
                else:
                    self.send(chat_id, "Last scan: {} — {}\nFinished: {}\n{}\nLog: {}".format(
                        state.get("domain", "?"),
                        state.get("status", "unknown"),
                        timestamp(state.get("finished_at")),
                        proxy_note,
                        state.get("log", ""),
                    ))
            return

        if command == "report":
            domain = normalize_domain(argument) if argument else None
            if not domain:
                state = self._read_state()
                domain = state.get("domain")
            if not domain or not self.scope_allows(domain):
                self.send(chat_id, "Specify an allowlisted domain: /report example.com")
                return
            active = self.active_scan()
            if active and active.get("domain") == domain:
                self.send(chat_id, "The scan for {} is still running; request the report after it finishes.".format(domain))
                return
            report, text = self.latest_report(domain)
            if not report or text is None:
                self.send(chat_id, "No report found yet for {}. Check /status and the scan host.".format(domain))
                return
            self.send(chat_id, "Latest report for {}\n{}\n\nDetailed findings: /findings {}".format(domain, report, domain))
            self.send_chunked(chat_id, text)
            return

        if command in ("findings", "finding", "bugs"):
            domain = self._report_domain(argument)
            if not domain:
                self.send(chat_id, "Usage: /findings example.com (an allowlisted domain)")
                return
            path, text = self.markdown_report(domain)
            if text is None:
                self.send(chat_id, "No Markdown report yet for {}. Run /scan, then /report.".format(domain))
                return
            section = self.markdown_section(text, "Findings")
            if not section:
                self.send(chat_id, "The report for {} has no findings section yet.".format(domain))
                return
            self.send(chat_id, "Findings for {} (what it is / impact / how to check / fix)\n{}".format(domain, path))
            self.send_chunked(chat_id, section)
            return

        if command in ("passive", "osint"):
            domain = self._report_domain(argument)
            if not domain:
                self.send(chat_id, "Usage: /passive example.com (an allowlisted domain)")
                return
            toolkit = self.script.parent / "bugbounty-toolkit"
            if not (toolkit / "main.py").is_file():
                self.send(chat_id, "Passive toolkit not found next to the script.")
                return

            venv_python = toolkit / ".venv" / "bin" / "python"
            python_exe = str(venv_python) if venv_python.is_file() else "python3"

            # The toolkit enforces its own scope; record the domain the same way
            # recon.sh does instead of editing its YAML by hand.
            try:
                scope_file = toolkit / "data" / "extra_scope.txt"
                scope_file.parent.mkdir(parents=True, exist_ok=True)
                existing = set()
                if scope_file.is_file():
                    for line in scope_file.read_text(encoding="utf-8").splitlines():
                        value = line.split("#", 1)[0].strip()
                        if value:
                            existing.add(value)
                if domain not in existing:
                    with scope_file.open("a", encoding="utf-8") as handle:
                        handle.write(domain + "\n")
            except OSError as error:
                self.send(chat_id, "Could not record the passive scope: {}".format(error))
                return

            self.send(chat_id, "Running the passive toolkit for {} (OSINT + headers). This takes a minute.".format(domain))
            try:
                result = subprocess.run(
                    [python_exe, "main.py", domain],
                    cwd=str(toolkit),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=900,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                self.send(chat_id, "Passive run failed: {}".format(error))
                return

            reports = sorted(
                (path for path in toolkit.glob("reports/{}-*.md".format(domain)) if path.is_file()),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if not reports:
                output = ANSI_ESCAPE.sub("", result.stdout or "").strip()
                self.send(chat_id, "No passive report was produced. Last output: {}".format(output[-1500:] or "none"))
                return

            report = reports[0]
            text = self._read_text(report) or ""
            section = self.markdown_section(text, "Findings")
            self.send(chat_id, "Passive report for {}\n{}".format(domain, report))
            self.send_chunked(chat_id, section or "_The passive report has no findings section yet._")
            return

        if command in ("log", "logs"):
            domain = self._report_domain(argument)
            if not domain:
                self.send(chat_id, "Usage: /log example.com (an allowlisted domain)")
                return

            parts = ["Logs for {}".format(domain)]
            scan_log = self.scan_log_path(domain)
            if scan_log is not None:
                text = self._read_text(scan_log) or ""
                parts.append("\nScan log ({}):\n{}".format(scan_log.name, "\n".join(text.splitlines()[-60:])))
            pipeline = self.pipeline_log_path(domain)
            if pipeline is not None:
                text = self._read_text(pipeline) or ""
                parts.append("\nPipeline log ({}):\n{}".format(pipeline.name, "\n".join(text.splitlines()[-60:])))
            stages = self.stage_summary(domain)
            if stages:
                parts.append("\nStages:\n{}".format(stages))
            if len(parts) == 1:
                self.send(chat_id, "No log found yet for {}. Run /scan first.".format(domain))
                return
            self.send_chunked(chat_id, "\n".join(parts))
            return

        if command in ("doctor", "tools"):
            try:
                result = subprocess.run(
                    [self.bash, str(self.script), "--check"],
                    cwd=str(self.script.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                    check=False,
                )
                output = ANSI_ESCAPE.sub("", result.stdout or "").strip()
                if not output:
                    output = "Environment check returned no output (exit {}).".format(result.returncode)
                self.send_chunked(chat_id, output)
            except (OSError, subprocess.TimeoutExpired) as error:
                self.send(chat_id, "Environment check failed: {}".format(error))
            return

        self.send(chat_id, "Unknown command. Send /help for the command list.")

    def run(self):
        self.api_call("getMe", timeout=15)
        print("Recon Pro Telegram bot is running. Scope file: {}".format(self.scope_file), flush=True)
        backoff = 2
        while True:
            self.refresh_scan_state()
            try:
                updates = self.api_call(
                    "getUpdates",
                    {
                        "offset": self.offset,
                        "timeout": 25,
                        "allowed_updates": json.dumps(["message", "callback_query"]),
                    },
                    timeout=35,
                ) or []
                backoff = 2
                for update in updates:
                    try:
                        self.handle_update(update)
                    except (BotError, OSError, ValueError, KeyError) as error:
                        print("Update handling failed: {}".format(error), file=sys.stderr, flush=True)
                    try:
                        self.offset = max(self.offset, int(update.get("update_id", -1)) + 1)
                        self._save_offset()
                    except (TypeError, ValueError, OSError):
                        pass
            except BotError as error:
                if "HTTP 409" in str(error) or "Conflict" in str(error):
                    print("FATAL: Telegram polling conflict. Stop other bot processes using this token and disable any webhook before restarting.", file=sys.stderr, flush=True)
                    return 2
                print("Telegram polling error: {}".format(error), file=sys.stderr, flush=True)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)


def main():
    try:
        return ReconTelegramBot().run() or 0
    except KeyboardInterrupt:
        print("\nRecon Pro Telegram bot stopped.", flush=True)
        return 130
    except BotError as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
