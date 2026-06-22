# wpasec-notify

A lightweight daemon that polls your [wpa-sec.stanev.org](https://wpa-sec.stanev.org) account every 30 minutes and sends rich Discord notifications when new WiFi passwords are cracked.

## Features

- **Rich Discord embeds** - each crack gets its own embed with SSID, BSSID, password, router vendor, and password type
- **IEEE OUI vendor lookup** - identifies the router manufacturer from the MAC address using the official IEEE database (auto-refreshes weekly, no API key required)
- **Password analysis** - categorizes passwords as numeric-only, common/default, has special chars, etc., with color-coded embeds
- **Randomized MAC detection** - correctly identifies locally administered / randomized MAC addresses
- **Milestone notifications** - gold trophy embeds at 10, 25, 50, 100, 200, 500, and 1000 total cracks
- **Daily digest** - summary embed every morning with total cracked, average password length, and password type breakdown
- **CSV export** - every new crack is appended to `cracks.csv` with timestamp, vendor, and password type
- **Log rotation** - log file capped at 1 MB with 3 backups
- **No external dependencies** - pure Python standard library

## Setup

**1. Clone the repo:**
```bash
git clone https://github.com/yourusername/wpasec-notify.git
cd wpasec-notify
```

**2. Configure:**
```bash
cp config.env.example config.env
```

Edit `config.env` and fill in your values:

```bash
WPASEC_KEY=your_wpasec_key_here
DISCORD_WEBHOOK=https://discord.com/api/webhooks/your/webhook/here
POLL_INTERVAL=30
```

- **WPASEC_KEY** - found on your [wpa-sec.stanev.org](https://wpa-sec.stanev.org) profile page
- **DISCORD_WEBHOOK** - create one under your Discord server's channel settings → Integrations → Webhooks
- **POLL_INTERVAL** - how often to check for new cracks, in minutes (default: 30)

**3. Make `run.sh` executable:**
```bash
chmod +x run.sh
```

## Usage

**Run as a background daemon:**
```bash
./run.sh &
```

**Run a single poll cycle and exit:**
```bash
./run.sh --once
```

**Print pot file stats (no Discord notification):**
```bash
./run.sh --stats
```

**Force-send the daily digest to Discord immediately:**
```bash
./run.sh --force-digest
```

**Stop the daemon:**
```bash
pkill -f wpasec_notify.py
```

## Discord Notifications

### New crack
Each cracked network fires an embed showing:

| Field | Example |
|---|---|
| SSID | `MyHomeNetwork` |
| BSSID | `aa:bb:cc:dd:ee:ff` |
| Password | `hunter2` |
| Router Vendor | `TP-Link Corporation Limited` |
| Password Type | `Alphanumeric` |

Embed color reflects password strength - red for weak/short/common, orange for letters-only, green for alphanumeric or special chars.

### Milestone
Gold embed when your total crack count hits 10, 25, 50, 100, 200, 500, or 1000.

### Daily digest
Blue summary embed on the first poll of each day showing total cracked, average password length, and a full password type breakdown.

## Files

| File | Description |
|---|---|
| `wpasec_notify.py` | Main script |
| `run.sh` | Wrapper that loads `config.env` and passes args through |
| `config.env` | Your credentials (never commit this) |
| `config.env.example` | Template for new installs |

The following files are created automatically at runtime:

| File | Description |
|---|---|
| `oui_db.json` | IEEE OUI vendor database cache (auto-refreshes weekly) |
| `seen_cracks.json` | Cache of already-notified cracks |
| `state.json` | Milestone and daily digest state |
| `cracks.csv` | Append-only log of all new cracks |
| `wpasec.log` | Rotating log file |

## Requirements

- Python 3.9+
- `curl` (for sending Discord webhooks... just kidding, it uses `urllib`)
- A wpa-sec.stanev.org account with uploaded captures
- A Discord webhook URL
