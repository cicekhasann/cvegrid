# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-11-02

### Added
- **Tech Stack Taxonomy & Classification Engine**:
  - **Deterministic Classifier** (`internal/ingestion/classifier.go`): Autonomous classification module mapping vulnerabilities to high-level ecosystems (`KERNEL_OS`, `RUNTIME_LANG`, `LIB_PKG`, `ENTERPRISE_APP`, `NETWORK_HW`) and extracting normalized technology tags (`Linux Kernel`, `FreeBSD`, `Windows NT`, `XNU`, `C/C++`, `PHP`, `Python`, `Go`, `Rust`, `Java / Spring`, `OpenSSL`, `glibc`, `libcurl`, `SQLite`, `Apache`, `Nginx`, etc.).
  - **Memory Corruption Inference**: Automatic detection of `C/C++` systems software flaw associations from memory safety CWEs (`CWE-787`, `CWE-416`, `CWE-120`, `CWE-476`).
- **Database Schema & Query Upgrade**:
  - Added `ecosystem TEXT DEFAULT ''` and `tech_tags TEXT DEFAULT '[]'` columns to `vulnerabilities` table.
  - Created performance index `idx_cve_ecosystem ON vulnerabilities(ecosystem)`.
  - Automated idempotent column migrations in `internal/database/db.go`.
  - Added `ecosystem` and `tech_tag` query filters to `GetVulnerabilities()`.
  - Enhanced `GetStats()` with 4 dedicated telemetry slices: `TopVendors`, `TopLanguages`, `TopPackages`, and `TopKernels`.
- **Segmented Ecosystem Telemetry UI (Right Column)**:
  - Transformed vendor metrics into an interactive 4-tab container: `[ VENDORS ]` | `[ LANGUAGES ]` | `[ LIBS & PKGS ]` | `[ KERNEL & OS ]`.
  - Rendered capacity progress bars for every technology slice with instant click-to-filter capability.
- **Dossier Technology Stack Integration (Center Column)**:
  - Rendered detected technology pills (`[ STACK: C/C++ ]`, `[ CORE: Linux Kernel ]`, `[ PKG: OpenSSL ]`, `[ ECOSYSTEM: KERNEL_OS ]`) in the Dossier headline.
  - Interactive pill click-to-filter support in live matrix.
  - Enriched Attack Kill Chain Stage 01 with target technology stack details.

## [1.3.0] - 2026-11-02

### Added
- **Interactive Analytics & Micro-Charts**:
  - **Top Vendors Progress Bars**: Horizontal capacity bars illustrating relative vulnerability volume with instant vendor click-to-filter capability.
  - **Attack Vector Segmented Ratio Bar**: Multi-segmented horizontal ratio bar (Sky Blue for Network/Remote, Amber for Local/Privesc, Slate for Physical/Other) with interactive segment and legend toggle filtering.
  - **Interactive EPSS Probability Tiers**: Interactive filter buttons (`CRITICAL > 80%`, `HIGH 50% - 80%`, `LOW < 50%`) with active selection highlights and instantaneous SQL filtering.
- **Dynamic Attack Kill Chain Visualizer**:
  - 3-stage interactive Kill Chain Flow connecting Initial Access Vector (with authentication requirements), Exploit Mechanism (MITRE CWE classification and flaw analysis), and Blast Radius/Impact (RCE, Privilege Escalation, or pulsing `🚨 RANSOMWARE WEAPONIZED` alert).
  - Subtle glowing directional connectors (`──►`) and responsive state transitions.
- **Threat Activity Mini Heatmap**:
  - 30-day discrete threat velocity heatmap strip located directly below the Top Telemetry HUD.
  - Dynamic cell color intensity ranging from muted slate (`lvl-0`) to bright crimson (`lvl-crit`).
  - Interactive tooltip displaying date, total count, and critical counts.
  - Single-click date filtering with active selection indicator and quick reset control.
- **Live Matrix Telemetry & Global Hotkeys**:
  - Table EPSS micro progress bar with pulsing crimson indicator dot for critical scores (> 80%).
  - Prominent crimson `[RANSOM]` badge in table rows for rapid scanning.
  - Global hotkeys: `j`/`k` or `↑`/`↓` row navigation, `/` search focus, `p` tier switcher toggle, and `Esc` universal filter reset.

## [1.2.0] - 2026-11-02

### Added
- **CTI Vector Enrichment**:
  - `cwe_id`: MITRE Common Weakness Enumeration extraction and deterministic classification (e.g. CWE-787, CWE-416, CWE-89, CWE-78).
  - `epss_score` & `epss_percentile`: Exploit Prediction Scoring System baseline probabilities and global percentile ratings.
  - `ransomware_campaign`: CISA KEV ransomware crew tracking flag (1 = active threat actor utilization).
  - `cvss_vector`: Standardized CVSS v3.1 vector telemetry (e.g., `CVSS:3.1/AV:N/AC:L/...`).
  - `remediation_notes` & `due_date`: Action deadlines and vendor mitigation guidance.
- **Industrial CTI Workstation UI**:
  - Three-column layout: Left Live Threat Matrix (50%), Center Deep Dossier & Kill Chain (30%), Right Threat Intelligence & Metrics (20%).
  - Top Telemetry HUD with live heartbeat indicator, ransomware linked counters, and average EPSS risk.
  - High-density monospace typography (`JetBrains Mono`), dark matte charcoal palette (`#07090E`, `#0D1117`), and 0px rectangular sharp borders.
  - Purged all generic purple glowing dropshadows, rounded corners, and AI tropes.
- **Terminal TUI Parity**:
  - Enhanced Preview Panel and Full-screen Dossier Modal displaying CWE identifiers, EPSS probabilities, and vivid crimson `[RANSOMWARE: ACTIVE CAMPAIGN]` warning banners.
- **Story-Driven Human-Readable CTI**:
  - **Executive Summary (TL;DR)**: Plain-English, 1-2 sentence executive threat summary explaining what is broken and the real danger at first glance.
  - **3 Instant Badges**: `URGENCY` (Immediate Action Required / Schedule Maintenance / Monitor), `IN THE WILD` (Exploited Today with pulsating flame alert / Active in Wild), and `ACTION` (Patch Immediately / Isolate Port & Disconnect / Apply Vendor Mitigation).
  - **Curated Reads Recommender**: 2-3 high-value external references per vulnerability (📰 News & Incident Coverage via BleepingComputer/HackerNews, 🔬 Deep Technical Analysis & Vendor Bulletins, 🛠️ Official NIST NVD Specification).
  - **Plain-English CWE Explanations**: Human-readable explanations of underlying software weaknesses (e.g. CWE-787, CWE-416, CWE-89, CWE-78).
- **Dual-Tier Workstation UI**:
  - Tier 1 (Human-First Overview): Executive TL;DR card, clear action box with remediation deadlines, and clickable curated Intel Cards.
  - Tier 2 (Pro Inspector): Collapsible/tabbed deep technical telemetry containing granular EPSS percentile bars, full CVSS v3.1 vector strings, MITRE weakness explanations, and raw machine taxonomy.
- **Terminal TUI Parity**:
  - Reordered Preview Panel and full-screen Dossier Modal to place Executive TL;DR summaries, Instant Badges, and Curated Reads directly at the top before raw technical metadata.
- **Modern Engineering Dashboard UI/UX Refactoring**:
  - **Dual-Typography System**: Clean sans-serif stack (`Inter`, system-ui) for body text, headers, and checklists; monospace (`JetBrains Mono`, `Fira Code`) strictly for CVE IDs, numeric metrics, dates, CWE codes, and CVSS vector strings.
  - **Soft Zinc / Graphite Palette**: Replaced harsh neon-on-pitch-black with balanced modern dark surfaces (`#0B0D13` canvas, `#11141D` panel, `#171B26` cards with `#232936` borders, soft crimson `#F43F5E`, amber `#F59E0B`, sky blue `#0284C7`/`#38BDF8`, and emerald `#10B981`).
  - **Enhanced Stream Table Spacing**: Increased row padding (`10px 12px`), structured Target column hierarchy with bold product title on top and muted vendor name beneath, smooth hover (`#1A1F2C`), and active selection highlight (`border-left: 3px solid #38BDF8`).
  - **Smart Link Formatting & Action Checklist**: Replaced raw plaintext URLs with compact badge pills (`[ ↗ CISA Guidance ]`, `[ ↗ Vendor Advisory ]`, `[ ↗ Patch Details ]`) and spaced checklist items.
- **Database Graceful Column Migrations**:
  - Safe, automatic SQLite column migration checking for existing databases without data loss.

## [1.1.0] - 2026-11-02

### Added
- **Dual-Engine Architecture**: Integrated support for both Terminal TUI and Web Threat Console directly within a single static Go binary via `embed.FS`.
- **Interactive CLI Dispatcher**: Interactive TTY prompt offering immediate choice between `[1] Terminal TUI` and `[2] Web Threat Console`, with explicit flags (`-t`/`--tui` and `-w`/`--web`).
- **Web Threat Console**: Embedded dark-mode Cyber/SOC operations dashboard with real-time telemetry meters, interactive category tabs, top vendor chips, instant debounced search, and full dossier inspection modals.
- **Embedded REST API**: Native endpoints for `/api/vulnerabilities`, `/api/stats`, and `/api/sync` without external web framework dependencies.
- **Smart Port Hunting**: Default port changed to base 19840 with dynamic scan forward (+10 ports) and ephemeral fallback on address collision.
- **Background Daemon Service Management**: Native background service lifecycle commands (`cvegrid web start`, `cvegrid web stop`, `cvegrid web status`, and `-w -d` / `--daemon`) with XDG PID state tracking.
- **Dynamic System Localization (TR/EN)**: Automatic locale detection via `LANG`/`LC_ALL` with localized interactive CLI menus and daemon status reports.

## [1.0.0] - 2026-11-02


### Added
- **Core TUI Workstation**: Implemented dual-pane workstation interface with 52% threat stream table and 48% real-time telemetry preview box using Bubbletea and Lipgloss.
- **Pure Go Architecture**: Zero-CGO database driver utilizing `modernc.org/sqlite` for static binary generation without native C toolchains.
- **Streaming Ingestion Engine**: Memory-efficient streaming JSON deserializer parsing CISA Known Exploited Vulnerabilities catalog.
- **Domain Heuristics**: Automated heuristic categorization for `KERNEL & OS`, `FIREWALL & NET`, `MEMORY SAFETY`, `SERVICES & APPS`, and attack vectors (`NETWORK / REMOTE`, `LOCAL / PRIVESC`, `LOCAL / INTERNAL`).
- **Telemetry HUD**: Real-time counters for total records, critical-severity flaws, high-severity flaws, sync state, and last sync timestamp.
- **Deep Dossier Modal**: Full-screen centered double-border modal overlay providing complete technical vulnerability analysis, remediation notices, and official references.
- **Live Search**: Instantaneous substring and regex matching across CVE ID, vendor, and product fields.
- **External Integration**: One-key browser dispatch (`o`) to NIST National Vulnerability Database bulletin via `xdg-open`.
- **Asynchronous Sync**: Background feed synchronization via `r` key or headless CLI flag `--sync`.
- **Terminal Resize Guard**: Automatic detection and graceful fallback banner for terminals smaller than 90x20.
- **XDG Specification Compliance**: Persistent SQLite state located at `$XDG_DATA_HOME/cvegrid/cvegrid.db`.
- **Manual Page**: Production-grade Unix ROFF manpage (`man/cvegrid.1`).
- **Comprehensive Test Suite**: In-memory database query/transaction tests and parser classification tests.
