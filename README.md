MBSD Tool — Local GUI Vulnerability Scanner (Python)

Overview
- Local desktop GUI app built with PySide6 (Qt).
- Enumerates paths under a target domain, crawls internal links, and runs basic vulnerability checks.
- Embeds a browser-like panel to reconstruct pages (HTML/CSS/JS) and show AI-driven interactions.
- Uses a local Ollama model for AI logic to simulate manual testing flows.
- Exports scan results to Markdown and JSON reports.

Key Features
- Target input → path enumeration (dictionary + crawl) with scope control.
- Scan modes: Safe, Normal, Attack (increasing intrusiveness).
- Agent Browser: Qt WebEngine view with animated cursor and scripted actions from AI.
- Report export with vulnerability name, severity, evidence, and reproduction steps.
 - Baseline diff: save a JSON baseline after a scan and later load it to see New / Unresolved / Fixed findings.

Quick Start (Native)
1) Prerequisites:
   - Python 3.10+
   - Ollama installed and running locally (default: http://localhost:11434)
   - `pip install -e .`
2) Run:
   - `python -m mbsd_tool`

Quick Start (Docker)
- For Linux with X11 display sharing:
  1) `docker compose up --build`
  2) Allow X access: `xhost +local:` (and revoke later with `xhost -local:`)
  3) The app window displays on the host X server.

  Note: For macOS/Windows, X11 display requires XQuartz (macOS) or an X server (Windows). Alternatively, use the `novnc` service variant (to be enabled later) to view the GUI in a browser.

Directory Layout
- `mbsd_tool/` — App package
  - `gui/` — Qt GUI, tabs, web panel, styles
  - `core/` — Crawler, scanner, agent, report, models
  - `config/` — Settings and constants
  - `resources/` — Icons and styles (QSS)
- `docker/` — Dockerfile(s) and helper scripts

Current Status
- Minimal working GUI with tabs
- Basic path enumeration (wordlist + crawl)
- Basic passive checks (headers, TLS, status anomalies)
- Agent browser stub + Ollama integration (safe fallbacks if Ollama unreachable)
- Markdown/JSON export
 - Baseline comparison UI in Results tab (import/export JSON)

Change Tracking (Baseline Diff)
- After a scan, open the Results/Report tab and click "比較用ファイル保存(JSON)" to save a baseline file.
- On a subsequent scan of the same target, click "前回ファイル読込" to load the previous baseline.
- The details table then shows a 状態 column marking each current finding as 新規 or 未解決; a separate dialog lists 修正済み.
- Baseline files are plain JSON. You can also load a previously exported JSON ScanResult; it will be converted automatically.

Roadmap
- Expand active tests per mode, plugin-style scanner architecture
- Add login workflows, session management, and form-filling strategies
- Enable noVNC-based container UX for macOS/Windows users
