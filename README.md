# `cvegrid` // Go-Native Vulnerability & Threat Intelligence Terminal

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Pure Go](https://img.shields.io/badge/CGO-disabled-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`cvegrid` is a high-performance, single-binary, terminal-native (TUI) security telemetry and CVE dossier exploration utility written in pure Go. It streams, classifies, and indexes the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog directly inside an interactive, keyboard-driven security operations workstation.

```text
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ ⚡ CVEGRID v1.0.0-PROD  TOTAL: 1,328  CRIT (9.0+): 342  HIGH: 986    ● FEED: CISA KEV   │
 ├────────────────────────────────────────────────────────────────────────────────────────┤
 │ [1: ALL]  [2: KERNEL & OS]  [3: FIREWALL & NET]  [4: MEMORY SAFETY]  [5: SERVICES & APPS] │
 ├─────────────────────────────────────────────┬──────────────────────────────────────────┤
 │ DATE        CVE ID          TARGET          │ CVE-2024-21887          CRITICAL 9.8     │
 │ 2024-01-10  CVE-2024-21887  Ivanti Connect  │ ──────────────────────────────────────── │
 │ 2023-07-24  CVE-2023-38606  Apple macOS     │ [NETWORK / REMOTE]  [FIREWALL & NET]     │
 │ 2023-04-11  CVE-2023-28252  Microsoft Win   │ TARGET: Connect Secure (Ivanti)          │
 │ 2023-10-10  CVE-2023-44487  IETF HTTP/2     │ DATE ADDED: 2024-01-10                   │
 │                                             │                                          │
 │                                             │ TECHNICAL SUMMARY                        │
 │                                             │ An unauthenticated command injection     │
 │                                             │ vulnerability enables remote execution.  │
 │                                             │                                          │
 │                                             │ [Enter] Deep Dossier   [o] NIST NVD      │
 ├─────────────────────────────────────────────┴──────────────────────────────────────────┤
 │ [j/k] Nav  [1-5] Category  [/] Search  [Enter] Dossier  [o] NIST  [r] Sync  [q] Quit   │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Highlights & Core Directives

- **Zero CGO (Pure Go Binary):** Built using `modernc.org/sqlite` instead of `mattn/go-sqlite3`. Compiles statically with `CGO_ENABLED=0` without requiring GCC, Musl, or native toolchains.
- **Asynchronous Pipeline & Zero UI Freeze:** All HTTP fetches, streaming JSON deserialization, and database updates execute in isolated goroutines, dispatching typed messages (`tea.Msg`) to the Bubble Tea event loop. The UI maintains a constant 60 FPS under heavy ingestion.
- **Memory-Efficient Streaming Ingestion:** Employs streaming JSON token decoders (`json.NewDecoder`) to ingest large threat feeds with minimal heap allocation.
- **Heuristic Threat Classification:** Automatically categorizes threats into specialized operational buckets (`KERNEL & OS`, `FIREWALL & NET`, `MEMORY SAFETY`, `SERVICES & APPS`, `OTHER`) and isolates attack vectors (`NETWORK / REMOTE`, `LOCAL / PRIVESC`, `LOCAL / INTERNAL`).
- **Deep Dossier Inspection Overlay:** Full-screen double-bordered centered modal (`╔═╗`, `║`, `╚═╝`) displaying complete vulnerability analysis, remediation notices, and official NIST/CISA links.
- **XDG Base Directory Compliance:** Database resides strictly at `$XDG_DATA_HOME/cvegrid/cvegrid.db` (falling back to `~/.local/share/cvegrid/cvegrid.db`).
- **Terminal Resize Guard:** Automatically detects window geometry and renders an adaptive notification if the terminal is smaller than `90x20`.

---

## Directory Layout

```text
cvegrid/
├── cmd/
│   └── cvegrid/
│       └── main.go                  # Entrypoint, CLI flag parsing, signal capture (SIGINT, SIGTERM)
├── internal/
│   ├── config/
│   │   └── xdg.go                   # XDG Base Directory specification resolver & path init
│   ├── daemon/
│   │   └── daemon.go                # Background daemon lifecycle manager & PID persistence
│   ├── database/
│   │   ├── db.go                    # modernc.org/sqlite connection setup & schema bootstrap
│   │   └── repository.go            # Thread-safe data access layer (queries, transactions, indexes)
│   ├── ingestion/
│   │   ├── client.go                # HTTP client with timeouts, User-Agent, and retry backoff
│   │   ├── parser.go                # Streaming JSON deserializer & heuristic classification engine
│   │   └── sync.go                  # Asynchronous sync coordinator dispatching tea.Cmd messages
│   ├── locale/
│   │   └── locale.go                # Dynamic TR/EN locale detector & prompt localization
│   ├── model/
│   │   └── cve.go                   # Domain models, category enums, and score calculation structs
│   ├── ui/
│       ├── app.go                   # Bubbletea Root Model, View dispatcher & event router
│       ├── components/
│       │   ├── header.go            # Top HUD telemetry badges (Counters, Sync state, Active feed)
│       │   ├── tabs.go              # Category filter tab-bar
│       │   ├── stream_table.go      # Chronologically sorted, scrollable threat stream table
│       │   ├── preview_panel.go     # Right-hand dossier telemetry preview box
│       │   └── dossier_modal.go     # Full-screen deep inspection modal overlay (triggered by Enter)
│       ├── styles/
│       │   └── theme.go             # Centralized Lipgloss palettes (Slate, Cyan, Emerald, Neon Red)
│       └── keys/
│           └── keymap.go            # Vim-friendly and intuitive keybinding bindings
│   └── web/
│       ├── assets/
│       │   ├── index.html           # Dark cyber SOC web operations dashboard
│       │   ├── style.css            # Dark SOC theme and glassmorphism styling
│       │   └── app.js               # Reactive telemetry and asynchronous REST client
│       └── server.go                # Embedded HTTP server, smart port hunting & REST API (embed.FS)
├── man/
│   └── cvegrid.1                    # Production-grade ROFF manual page
├── tests/
│   ├── repository_test.go           # In-memory SQLite transaction and query tests
│   ├── parser_test.go               # Ingestion categorization and vector parsing tests
│   ├── web_test.go                  # Embedded Web server and REST API tests
│   └── daemon_test.go               # Port hunting, locale detection, and daemon tests
├── Makefile                         # Unified development, test, and build automation
├── CHANGELOG.md                     # Semantic versioning & Keep a Changelog standard
├── README.md                        # Documentation with installation, flags, and shortcuts
├── go.mod
└── go.sum
```

---

## Getting Started

### Prerequisites

- Go 1.22+ (tested on Go 1.26)
- Standard Unix terminal emulator (minimum 90 columns by 20 lines)

### Building from Source

```bash
git clone https://github.com/cicekhasann/cvegrid.git
cd cvegrid

# Build static binary
make build

# The resulting binary is completely static:
file bin/cvegrid
# bin/cvegrid: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

### Running Tests

```bash
# Run unit tests and race condition detector
make test
```

### Running the Application

```bash
# Interactive Mode (Auto-detects TR/EN locale and prompts interface selection)
./bin/cvegrid

# Launch directly into Terminal TUI
./bin/cvegrid -t

# Launch embedded Web Threat Console in foreground (default base port: 19840)
./bin/cvegrid -w

# Background Daemon Service Management (detach from shell, auto-opens browser)
./bin/cvegrid web start
# or via flag:
./bin/cvegrid -w -d

# Check daemon service status, uptime, PID, and bound port
./bin/cvegrid web status

# Gracefully stop running background daemon service
./bin/cvegrid web stop

# Headless CLI sync mode (ingests feed into local database without launching UI)
./bin/cvegrid -sync
```

---

## Command Line Flags & Subcommands

| Command / Flag | Type | Description |
|---|---|---|
| `web start` | `command` | Launch web dashboard as detached background daemon service |
| `web stop` | `command` | Gracefully terminate active background daemon service |
| `web status` | `command` | Inspect status, PID, URL, and uptime of background service |
| `-t`, `--tui` | `bool` | Explicitly launch the Bubbletea Terminal TUI workstation |
| `-w`, `--web` | `bool` | Launch embedded Web Threat Console on `127.0.0.1:<port>` |
| `-d`, `--daemon` | `bool` | Run web dashboard as detached background daemon |
| `-port`, `-p` | `int` | Custom base HTTP port (default: `19840` with smart forward port hunting) |
| `-sync` | `bool` | Headlessly synchronize latest CISA KEV catalog into local SQLite DB and exit |
| `-db <path>` | `string` | Custom path to SQLite database (default: `$XDG_DATA_HOME/cvegrid/cvegrid.db`) |
| `-feed <url>` | `string` | Custom threat intelligence feed URL |
| `-v`, `-version` | `bool` | Print version information and exit |

---

## Keyboard Shortcuts

| Keybinding | Action |
|---|---|
| `j` / `Down` | Move selection down |
| `k` / `Up` | Move selection up |
| `g` / `Home` | Jump to newest (top) record |
| `G` / `End` | Jump to oldest (bottom) record |
| `PageUp` / `b` | Scroll page up |
| `PageDown` / `f` | Scroll page down |
| `1` - `5` | Switch category tabs (`1: ALL`, `2: KERNEL & OS`, `3: FIREWALL & NET`, `4: MEMORY SAFETY`, `5: SERVICES & APPS`) |
| `/` | Live regex / substring search prompt |
| `Enter` | Open full-screen deep dossier inspection modal |
| `o` | Open official NIST NVD vulnerability bulletin in default browser |
| `r` | Trigger asynchronous background feed synchronization |
| `Esc` | Clear search prompt / close active inspection modal |
| `q` / `Ctrl+C` | Graceful shutdown |

---

## Classification Heuristics

`cvegrid` automatically classifies threat intelligence into high-value security sectors:

- **KERNEL & OS:** `linux`, `kernel`, `freebsd`, `unix`, `bpf`, `driver`, `windows`, `macos`.
- **FIREWALL & NET:** `firewall`, `zyxel`, `cisco`, `fortinet`, `pfsense`, `vpn`, `ipsec`, `wireguard`, `router`, `pan-os`, `tcp`.
- **MEMORY SAFETY:** `use-after-free`, `buffer overflow`, `heap`, `stack`, `out-of-bounds`, `race condition`, `memory corruption`.
- **SERVICES & APPS:** `nginx`, `apache`, `openssl`, `ssh`, `sudo`, `redis`, `postgres`, `docker`, `exchange`.
- **Attack Vectors:** Pre-auth and remote network vectors are flagged as `NETWORK / REMOTE`; privilege escalations as `LOCAL / PRIVESC`; others as `LOCAL / INTERNAL`.
- **Severity & Scoring:** References to RCE, unauthenticated access, or use-after-free are scored as `CRITICAL (9.8)`. Standard exploited vulnerabilities default to `HIGH (7.5)`.

---

## License

MIT License. Copyright (c) 2026.
