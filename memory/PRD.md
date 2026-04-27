# NetScan - Mini Nessus

A mobile-first network scanner powered by **Nmap**, packaged as an Expo Router app with a FastAPI backend.

## Stack
- **Frontend**: Expo Router (React Native) - tab navigation (Scan / History / About) + scan detail screen
- **Backend**: FastAPI + Motor (MongoDB)
- **Scanner**: System `nmap` invoked via `asyncio.create_subprocess_exec`, output parsed from XML (`-oX -`)
- **Storage**: MongoDB collection `scans` (UUIDs, no ObjectId leaks)

## Features
- 7 scan modes: Quick (-F), Full (-p-), Service (-sV), OS (-O), Intense (-A), **Vuln (NSE scripts)**, Custom (user flags)
- All presets force TCP connect scan (`-sT`) since the container lacks raw-socket privileges
- **NSE script whitelist** for custom flags (vuln, vulners, safe, default, discovery, banner, http-*, ssl-*, smb-os-discovery, ssh-*, ftp-*, smtp-commands, dns-recursion). Blocks `--script-args`, `-iL`, `-iR`, and any non-whitelisted script
- Real-time status polling with terminal-style ASCII progress
- Parsed host/port table (port, state, service, product, version)
- Nessus-style vulnerability hints with Critical / High / Medium / Low / Info severity
- Heuristic findings for telnet, ftp, rdp, redis, mongodb, mysql, postgres, smb, vnc, etc.
- Outdated OpenSSH detection (< v7)
- **PDF export** of completed scans via `GET /api/scans/{id}/pdf` (reportlab) — full report with metadata, findings table, host/port tables
- Scan history persisted to MongoDB; tap to revisit; trash icon to delete; download icon to export PDF
- Input validation: target regex + dangerous shell metachar blocklist on custom flags

## API
- `GET /api/` - health + nmap status
- `GET /api/scan-types` - scan presets
- `POST /api/scans` `{target, scan_type, custom_flags?}` - creates and starts scan
- `GET /api/scans` - list history (newest first)
- `GET /api/scans/{id}` - poll for status / results
- `GET /api/scans/{id}/pdf` - download PDF report
- `DELETE /api/scans/{id}` - remove a scan

## Setup
- Nmap installed via `apt-get install -y nmap`
- No external API keys required (no LLM / 3rd party integrations)
- Mongo URL & DB name come from `backend/.env`

## Security Hardening
- Target regex validation (only `A-Za-z0-9._-:/,` allowed)
- Custom-flag shell metachar blocklist (`; & | $ \` < > " '`)
- NSE script whitelist (vuln, vulners, safe, default, banner, http-*, ssl-*, ssh-*, ftp-*, smb-os-discovery, etc.)
- Blocks `--script-args`, `-iL`, `-iR` (file-read / mass-target risks)
- Forces `-sT` (TCP connect) so the scanner runs without raw-socket privileges
- Concurrent scan cap (`MAX_CONCURRENT_SCANS = 3`) via asyncio.Semaphore to prevent resource abuse
- Hard 600s per-scan timeout; subprocess killed on overrun
- In-app legal warning surfaced on scan screen and About tab

## Deployment Readiness
- Deployment health check: ✅ PASS (no blockers)
- Required env vars present: `EXPO_TUNNEL_SUBDOMAIN`, `EXPO_PACKAGER_HOSTNAME`, `EXPO_PACKAGER_PROXY_URL`, `EXPO_PUBLIC_BACKEND_URL`, `MONGO_URL`, `DB_NAME`
- ⚠️ **System dependency**: Production container must have `nmap` installed (`apt-get install -y nmap`). Backend gracefully reports `nmap_installed: false` and the UI shows "nmap NOT installed" if missing, so the app fails safe rather than crashing.

## Testing
- Backend pytest: 20/21 passing (1 long-running NSE test bumped to 300s timeout)
- Playwright e2e: full scan→detail→history→PDF flow green
