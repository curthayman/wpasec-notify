#!/usr/bin/env python3
"""
wpa-sec.stanev.org crack notifier
Polls your pot file, sends rich Discord embed notifications for new cracks,
exports to CSV, posts a daily digest, and performs MAC vendor + password analysis.
"""

import argparse
import csv
import fcntl
import json
import logging
import logging.handlers
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, date, timezone
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
WPASEC_KEY      = os.environ.get("WPASEC_KEY", "YOUR_KEY_HERE")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "YOUR_WEBHOOK_HERE")
POLL_INTERVAL   = int(os.environ.get("POLL_INTERVAL", "30")) * 60  # seconds

SCRIPT_DIR  = Path(__file__).parent
CACHE_FILE  = SCRIPT_DIR / "seen_cracks.json"
STATE_FILE  = SCRIPT_DIR / "state.json"
OUI_DB_FILE = SCRIPT_DIR / "oui_db.json"
CSV_FILE    = SCRIPT_DIR / "cracks.csv"
LOG_FILE    = SCRIPT_DIR / "wpasec.log"
POT_URL      = "https://wpa-sec.stanev.org/?api&dl=1"
MY_NETS_URL  = "https://wpa-sec.stanev.org/?my_nets"
OUI_CSV_URL  = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_REFRESH_DAYS = 7

MILESTONES = {10, 25, 50, 100, 200, 500, 1000}

# Embed colors
COLOR_GREEN    = 0x00FF88   # new crack (default)
COLOR_WEAK     = 0xFF4444   # weak/short password
COLOR_ORANGE   = 0xFFA500   # letters-only password
COLOR_STRONG   = 0x00CC44   # password with special chars
COLOR_GOLD     = 0xFFD700   # milestone
COLOR_BLURPLE  = 0x5865F2   # daily digest
COLOR_TEAL     = 0x00B4D8   # new handshake upload
# ──────────────────────────────────────────────────────────────────────────────


# ── Logging ───────────────────────────────────────────────────────────────────
def _setup_logging() -> logging.Logger:
    _logger = logging.getLogger("wpasec")
    if _logger.handlers:
        return _logger
    _logger.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    _logger.addHandler(fh)
    return _logger

logger = _setup_logging()
# ──────────────────────────────────────────────────────────────────────────────


# ── Instance lock (prevents duplicate notifications from two running daemons) ─
_lock_fd = None

def _acquire_instance_lock() -> None:
    global _lock_fd
    lock_path = SCRIPT_DIR / "wpasec.lock"
    _lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("ERROR: Another instance of wpasec-notify is already running.", file=sys.stderr)
        sys.exit(1)
# ──────────────────────────────────────────────────────────────────────────────


# ── Persistence ───────────────────────────────────────────────────────────────
def load_cache() -> set:
    if CACHE_FILE.exists():
        try:
            return set(json.loads(CACHE_FILE.read_text()))
        except (json.JSONDecodeError, ValueError):
            pass
    return set()


def save_cache(seen: set) -> None:
    CACHE_FILE.write_text(json.dumps(sorted(seen), indent=2))


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, ValueError):
            pass
    return {"milestones_hit": [], "last_digest_date": None, "last_submission_ts": None}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def load_oui_db() -> dict:
    """Return OUI→vendor dict, downloading/refreshing from IEEE when stale."""
    if OUI_DB_FILE.exists():
        try:
            stored = json.loads(OUI_DB_FILE.read_text())
            updated = date.fromisoformat(stored["updated"])
            if (date.today() - updated).days < OUI_REFRESH_DAYS:
                return stored["vendors"]
        except (json.JSONDecodeError, ValueError, KeyError):
            pass

    logger.info("Downloading IEEE OUI database...")
    req = urllib.request.Request(OUI_CSV_URL, headers={"User-Agent": "wpasec-notify/2.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw_csv = resp.read().decode("utf-8", errors="replace")

    vendors: dict[str, str] = {}
    reader = csv.DictReader(raw_csv.splitlines())
    for row in reader:
        oui = row["Assignment"].strip().upper()
        name = row["Organization Name"].strip()
        if oui and name:
            vendors[oui] = name

    OUI_DB_FILE.write_text(json.dumps({"updated": date.today().isoformat(), "vendors": vendors}))
    logger.info(f"IEEE OUI database loaded: {len(vendors):,} entries.")
    return vendors
# ──────────────────────────────────────────────────────────────────────────────


# ── Pot File ──────────────────────────────────────────────────────────────────
def fetch_pot() -> str:
    req = urllib.request.Request(POT_URL, headers={
        "User-Agent": "wpasec-notify/2.0",
        "Cookie": f"key={WPASEC_KEY}",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_pot(raw: str) -> list[dict]:
    """Format per line: MAC1:MAC2:SSID:PASSWORD (maxsplit=3 handles colons in SSID/pw)."""
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 3)
        if len(parts) == 4:
            entries.append({
                "mac1":     parts[0].strip(),
                "mac2":     parts[1].strip(),
                "ssid":     parts[2].strip(),
                "password": parts[3].strip(),
            })
    return entries
# ──────────────────────────────────────────────────────────────────────────────


# ── My Networks (submission tracking) ────────────────────────────────────────
def fetch_my_nets() -> str:
    req = urllib.request.Request(MY_NETS_URL, headers={
        "User-Agent": "wpasec-notify/2.0",
        "Cookie": f"key={WPASEC_KEY}",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_my_nets(html: str) -> list[dict]:
    """Return list of {bssid, ssid, type, timestamp} from My Networks page, newest first."""
    results = []
    for row in re.finditer(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL | re.IGNORECASE):
        row_html = row.group(1)
        if '<th' in row_html:
            continue
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row_html, re.DOTALL | re.IGNORECASE)
        if len(cells) < 5:
            continue
        bssid_m = re.search(r'([0-9a-f]{12})', cells[1], re.IGNORECASE)
        if not bssid_m:
            continue
        raw = bssid_m.group(1).lower()
        bssid = ':'.join(raw[i:i+2] for i in range(0, 12, 2))
        ssid = re.sub(r'<[^>]+>', '', cells[2]).strip()
        net_type = re.sub(r'<[^>]+>', '', cells[3]).strip()
        ts = re.sub(r'<[^>]+>', '', cells[-1]).strip()
        if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', ts):
            results.append({'bssid': bssid, 'ssid': ssid, 'type': net_type, 'timestamp': ts})
    return results
# ──────────────────────────────────────────────────────────────────────────────


# ── MAC Vendor Lookup ─────────────────────────────────────────────────────────
def get_vendor(mac: str, oui_db: dict) -> str:
    """Instant local lookup against the IEEE OUI database."""
    oui = mac.replace(":", "").replace("-", "")[:6].upper()
    if len(oui) >= 2:
        first_byte = int(oui[:2], 16)
        if first_byte & 0x02:
            return "Randomized/local MAC"
    return oui_db.get(oui, "Unknown")
# ──────────────────────────────────────────────────────────────────────────────


# ── Password Analysis ─────────────────────────────────────────────────────────
_COMMON_PASSWORDS = {
    "12345678", "123456789", "1234567890", "0987654321",
    "qwertyuiop", "qwerty", "asdfghjkl", "zxcvbnm",
    "password", "iloveyou", "sunshine", "princess", "welcome",
    "abc123", "monkey", "dragon", "master", "letmein",
    "admin", "root", "toor", "pass", "test",
}


def analyze_password(pw: str) -> tuple[str, int]:
    """Return (human-readable category, embed color int)."""
    if not pw:
        return ("Empty", COLOR_WEAK)
    if len(pw) < 8:
        return (f"Very short ({len(pw)} chars)", COLOR_WEAK)
    if pw.lower() in _COMMON_PASSWORDS:
        return ("Common/default", COLOR_WEAK)
    if len(set(pw)) == 1:
        return ("All same character", COLOR_WEAK)
    if re.fullmatch(r"\d+", pw):
        return ("Numeric only", COLOR_WEAK)
    if re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~]", pw):
        return ("Has special chars", COLOR_STRONG)
    if re.fullmatch(r"[a-zA-Z]+", pw):
        return ("Letters only", COLOR_ORANGE)
    return ("Alphanumeric", COLOR_GREEN)
# ──────────────────────────────────────────────────────────────────────────────


# ── CSV Export ────────────────────────────────────────────────────────────────
_CSV_FIELDS = ["timestamp", "mac1", "mac2", "ssid", "password", "vendor", "password_type"]


def append_to_csv(entries: list[dict]) -> None:
    is_new = not CSV_FILE.exists()
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        if is_new:
            writer.writeheader()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for e in entries:
            writer.writerow({
                "timestamp":     now,
                "mac1":          e["mac1"],
                "mac2":          e["mac2"],
                "ssid":          e["ssid"],
                "password":      e["password"],
                "vendor":        e.get("vendor", "Unknown"),
                "password_type": e.get("password_type", "Unknown"),
            })
# ──────────────────────────────────────────────────────────────────────────────


# ── Discord ───────────────────────────────────────────────────────────────────
def _post_discord(payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        DISCORD_WEBHOOK,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "wpasec-notify/2.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"Discord returned HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Discord returned HTTP {e.code}")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def send_discord_new_cracks(new_entries: list[dict], total: int) -> None:
    embeds = []
    for e in new_entries:
        pw_type, color = analyze_password(e["password"])
        embeds.append({
            "title": f"New Crack: {e['ssid']}",
            "color": color,
            "fields": [
                {"name": "SSID",          "value": f"`{e['ssid']}`",     "inline": True},
                {"name": "BSSID",         "value": f"`{e['mac1']}`",     "inline": True},
                {"name": "Password",      "value": f"`{e['password']}`", "inline": False},
                {"name": "Router Vendor", "value": e.get("vendor", "Unknown"), "inline": True},
                {"name": "Password Type", "value": pw_type,              "inline": True},
            ],
            "footer": {"text": f"Total cracked: {total}"},
            "timestamp": _utcnow_iso(),
        })

    # Discord allows max 10 embeds per message
    for i in range(0, len(embeds), 10):
        _post_discord({"embeds": embeds[i:i + 10]})


def send_discord_milestone(milestone: int, total: int) -> None:
    _post_discord({"embeds": [{
        "title": f"\U0001f3c6 Milestone: {milestone} Networks Cracked!",
        "color": COLOR_GOLD,
        "description": (
            f"Your wpa-sec account just hit **{milestone}** cracked networks "
            f"(total in pot file: {total}). Keep uploading!"
        ),
        "timestamp": _utcnow_iso(),
    }]})


def send_discord_daily_digest(entries: list[dict]) -> None:
    if not entries:
        return

    type_counts: dict[str, int] = {}
    lengths = []
    for e in entries:
        pw_type, _ = analyze_password(e["password"])
        type_counts[pw_type] = type_counts.get(pw_type, 0) + 1
        lengths.append(len(e["password"]))

    avg_len = sum(lengths) / len(lengths) if lengths else 0
    breakdown = "\n".join(
        f"• {t}: {c}"
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1])
    )

    _post_discord({"embeds": [{
        "title": "\U0001f4ca Daily wpa-sec Digest",
        "color": COLOR_BLURPLE,
        "fields": [
            {"name": "Total Cracked",       "value": str(len(entries)), "inline": True},
            {"name": "Avg Password Length", "value": f"{avg_len:.1f} chars", "inline": True},
            {"name": "Password Breakdown",  "value": breakdown or "—", "inline": False},
        ],
        "footer": {"text": date.today().isoformat()},
        "timestamp": _utcnow_iso(),
    }]})
# ──────────────────────────────────────────────────────────────────────────────


def send_discord_new_submission(new_nets: list[dict]) -> None:
    count = len(new_nets)
    lines = [
        f"`{n['bssid']}` — **{n['ssid']}** ({n['type']}) @ {n['timestamp']}"
        for n in new_nets[:10]
    ]
    if count > 10:
        lines.append(f"... and {count - 10} more")
    _post_discord({"embeds": [{
        "title": f"\U0001f4e1 {count} New Handshake{'s' if count > 1 else ''} Uploaded to wpa-sec",
        "color": COLOR_TEAL,
        "description": "\n".join(lines),
        "timestamp": _utcnow_iso(),
    }]})
# ──────────────────────────────────────────────────────────────────────────────


# ── Stats (--stats mode) ──────────────────────────────────────────────────────
def print_stats(entries: list[dict]) -> None:
    sep = "─" * 52
    print(f"\n{sep}")
    print(f"  wpa-sec pot file — {len(entries)} total entries")
    print(sep)

    type_counts: dict[str, int] = {}
    lengths = []
    for e in entries:
        pw_type, _ = analyze_password(e["password"])
        type_counts[pw_type] = type_counts.get(pw_type, 0) + 1
        lengths.append(len(e["password"]))

    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        bar = "█" * c
        print(f"  {t:<28}  {c:>4}  {bar}")

    if lengths:
        print(f"\n  Avg length : {sum(lengths)/len(lengths):.1f}")
        print(f"  Min / Max  : {min(lengths)} / {max(lengths)}")
    print(f"{sep}\n")
# ──────────────────────────────────────────────────────────────────────────────


# ── Poll Cycle ────────────────────────────────────────────────────────────────
def check(oui_db: dict, dry_run: bool = False) -> None:
    logger.info("Fetching pot file...")
    try:
        raw = fetch_pot()
    except urllib.error.URLError as e:
        logger.error(f"ERROR fetching pot file: {e}")
        return

    entries = parse_pot(raw)
    logger.info(f"Pot file has {len(entries)} total entries.")

    seen  = load_cache()
    state = load_state()

    new_entries = [e for e in entries if f"{e['mac1']}:{e['mac2']}" not in seen]

    if new_entries:
        logger.info(f"Found {len(new_entries)} NEW crack(s)!")
        for e in new_entries:
            e["vendor"] = get_vendor(e["mac1"], oui_db)
            pw_type, _ = analyze_password(e["password"])
            e["password_type"] = pw_type
            logger.info(
                f"  NEW: {e['ssid']} | {e['mac1']} | "
                f"pw={e['password']} | vendor={e['vendor']} | type={pw_type}"
            )

        if not dry_run:
            try:
                send_discord_new_cracks(new_entries, len(entries))
                logger.info("Discord notification sent.")
            except Exception as exc:
                logger.error(f"ERROR sending to Discord: {exc}")
            try:
                append_to_csv(new_entries)
                logger.info(f"Appended {len(new_entries)} row(s) to {CSV_FILE.name}.")
            except Exception as exc:
                logger.error(f"ERROR writing CSV: {exc}")

        for e in new_entries:
            seen.add(f"{e['mac1']}:{e['mac2']}")
        save_cache(seen)
    else:
        logger.debug("No new cracks since last check.")

    # ── Milestones ─────────────────────────────────────────────────────────────
    milestones_hit = set(state.get("milestones_hit", []))
    for m in sorted(MILESTONES):
        if len(entries) >= m and m not in milestones_hit:
            milestones_hit.add(m)
            logger.info(f"MILESTONE reached: {m} total cracks!")
            if not dry_run:
                try:
                    send_discord_milestone(m, len(entries))
                except Exception as exc:
                    logger.error(f"ERROR sending milestone: {exc}")
    state["milestones_hit"] = sorted(milestones_hit)

    # ── Daily digest (first poll of each new calendar day) ─────────────────────
    today_str = date.today().isoformat()
    if state.get("last_digest_date") != today_str:
        logger.info("New day — sending daily digest...")
        if not dry_run:
            try:
                send_discord_daily_digest(entries)
                logger.info("Daily digest sent.")
            except Exception as exc:
                logger.error(f"ERROR sending daily digest: {exc}")
        state["last_digest_date"] = today_str

    # ── Submission tracking ────────────────────────────────────────────────────
    try:
        nets = parse_my_nets(fetch_my_nets())
        if nets:
            newest_ts = nets[0]['timestamp']
            last_sub_ts = state.get('last_submission_ts')
            if last_sub_ts is None:
                state['last_submission_ts'] = newest_ts
                logger.info(f"Initialized submission tracker (newest: {newest_ts}).")
            elif newest_ts > last_sub_ts:
                new_nets = [n for n in nets if n['timestamp'] > last_sub_ts]
                logger.info(f"Found {len(new_nets)} new submission(s).")
                if not dry_run:
                    try:
                        send_discord_new_submission(new_nets)
                        logger.info("Submission notification sent.")
                    except Exception as exc:
                        logger.error(f"ERROR sending submission notification: {exc}")
                state['last_submission_ts'] = newest_ts
    except Exception as exc:
        logger.error(f"ERROR checking submissions: {exc}")

    save_state(state)
# ──────────────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="wpa-sec Discord notifier")
    parser.add_argument("--once", "-1", action="store_true",
                        help="Run one poll cycle then exit")
    parser.add_argument("--stats", action="store_true",
                        help="Print pot file stats and exit (no Discord)")
    parser.add_argument("--force-digest", action="store_true",
                        help="Send the daily digest immediately and exit")
    args = parser.parse_args()

    if WPASEC_KEY == "YOUR_KEY_HERE":
        print("ERROR: Set WPASEC_KEY environment variable.")
        sys.exit(1)
    if DISCORD_WEBHOOK == "YOUR_WEBHOOK_HERE":
        print("ERROR: Set DISCORD_WEBHOOK environment variable.")
        sys.exit(1)

    oui_db = load_oui_db()

    if args.stats:
        logger.info("Fetching pot file for stats...")
        try:
            raw = fetch_pot()
        except urllib.error.URLError as e:
            logger.error(f"ERROR: {e}")
            sys.exit(1)
        print_stats(parse_pot(raw))
        sys.exit(0)

    if args.force_digest:
        logger.info("Forcing daily digest...")
        try:
            raw = fetch_pot()
            send_discord_daily_digest(parse_pot(raw))
            logger.info("Daily digest sent.")
        except Exception as exc:
            logger.error(f"ERROR: {exc}")
            sys.exit(1)
        sys.exit(0)

    _acquire_instance_lock()

    logger.info(f"Starting wpa-sec notifier (polling every {POLL_INTERVAL // 60} minutes).")
    logger.info(f"Cache: {CACHE_FILE}  |  CSV: {CSV_FILE}  |  Log: {LOG_FILE}")

    if args.once:
        check(oui_db)
        sys.exit(0)

    try:
        while True:
            check(oui_db)
            logger.debug(f"Sleeping {POLL_INTERVAL // 60} minutes...")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Stopped.")


if __name__ == "__main__":
    main()
