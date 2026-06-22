# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python daemon that polls wpa-sec.stanev.org every 30 minutes for newly cracked WiFi passwords and sends rich Discord embed notifications. No dependencies beyond the Python standard library.

## Running the script

```bash
# Start as background daemon (normal use)
./run.sh &

# Single poll cycle then exit
./run.sh --once

# Print pot file stats to terminal (no Discord)
./run.sh --stats

# Force-send the daily digest to Discord immediately
./run.sh --force-digest
```

`run.sh` sources `config.env` before invoking `wpasec_notify.py "$@"`. Always use `run.sh` rather than calling Python directly so the env vars are loaded.

## Configuration

`config.env` holds three variables:
- `WPASEC_KEY` — wpa-sec.stanev.org API key
- `DISCORD_WEBHOOK` — Discord webhook URL
- `POLL_INTERVAL` — poll frequency in minutes (default 30)

## Architecture

Everything lives in `wpasec_notify.py`. The flow is:

1. **Startup** — `load_oui_db()` loads (or downloads) the IEEE OUI database into a dict. On first run or when `oui_db.json` is older than 7 days it fetches `https://standards-oui.ieee.org/oui/oui.csv` (~39k entries).
2. **Poll cycle** (`check()`) — fetches the pot file, diffs against `seen_cracks.json`, enriches new entries with vendor + password analysis, fires Discord embeds, appends to `cracks.csv`, checks milestones, and sends a daily digest on the first poll of each new day.
3. **Sleep** — waits `POLL_INTERVAL` minutes then repeats.

### Persistent files

| File | Purpose |
|---|---|
| `seen_cracks.json` | Set of `MAC1:MAC2` pairs already notified |
| `state.json` | Milestones hit + last digest date |
| `oui_db.json` | IEEE OUI vendor database (auto-refreshes weekly) |
| `cracks.csv` | Append-only log of all new cracks with metadata |
| `wpasec.log` | Rotating log (1 MB max, 3 backups) |

### Key functions

- `load_oui_db()` — downloads/caches IEEE OUI CSV; called once at startup
- `get_vendor(mac, oui_db)` — instant dict lookup; detects randomized MACs via `first_byte & 0x02`
- `analyze_password(pw)` — returns `(category_str, discord_color_int)`
- `send_discord_new_cracks()` / `send_discord_milestone()` / `send_discord_daily_digest()` — all use `_post_discord()` which POSTs JSON via `urllib.request`
- `check(oui_db)` — one full poll cycle; all side effects happen here

### Milestones

Defined as a set: `{10, 25, 50, 100, 200, 500, 1000}`. Once hit, stored in `state.json` so they never re-fire.
