# Veracode Bulk Upload & Scan

This tool automates creation of Veracode application profiles, artifact uploads, prescans, and full scan submissions. It supports both **deterministic** (prescan → poll → beginscan) and **autoscan** workflows.

---

## Features
- Bulk processing of artifacts in a folder (default: `*.zip`)
- Application profile naming convention: `<prefix><artifact_stem>`
- Automatic profile creation if missing
- Upload via `uploadfile.do` or `uploadlargefile.do`
- Prescan initiation for each artifact
- Two operating modes:
  - **autoscan** (default): prescan with `auto_scan=true` and exit (Veracode starts scans automatically when possible)
  - **deterministic**: prescan, poll until modules available, then start full scan with selected modules
- Sandbox support (`--sandbox-id`)
- Regional endpoint support (`--region-base`)
- Configurable polling interval and timeout

---

## Requirements
- Python 3.8+
- Packages:  
  ```bash
  pip install requests veracode-api-signing
  ```
- Veracode API credentials set via environment variables:
  ```bash
  export VERACODE_API_KEY_ID=xxxx
  export VERACODE_API_KEY_SECRET=xxxx
  ```
  or via `~/.veracode/credentials`.

---

## Usage

### Autoscan mode (default)
Prescan with `auto_scan=true`. Scans auto-start if module selection is not required:
```bash
python vc_bulk_upload.py   --artifacts-dir /path/to/builds   --mode autoscan
```

### Deterministic mode
Prescan → poll → beginscan (guarantees scans start even for new multi-module apps):
```bash
python vc_bulk_upload.py   --artifacts-dir /path/to/builds   --glob "*.zip"   --mode deterministic   --poll-interval 60   --verbose
```



---

## Key Options
- `--artifacts-dir`: directory containing packaged artifacts (**required**)
- `--glob`: file pattern (default: `*.zip`)
- `--prefix`: app name prefix
- `--criticality`: business criticality (default: `Medium`)
- `--region-base`: override API base URL (e.g. `https://analysiscenter.veracode.eu`)
- `--use-uploadlarge`: use `uploadlargefile.do` for big files
- `--sandbox-id`: target a specific sandbox
- `--select`: module selection mode (`all-top-level`, `from-prescan`, `previous`)
- `--mode`: `autoscan` (default) or `deterministic`
- `--poll-interval`: seconds between checks (deterministic mode)
- `--global-timeout`: max wait time for prescan readiness
- `--verbose`: enable detailed logs

---

## Best Practices
- Use **deterministic mode** for new apps or multi-module builds to guarantee scan start.  (Takes longer because of polling, keep in mind that pre-scan can take a couple of minutes.)
- Use **autoscan mode** for one-module apps or when modules were previously selected.  
- Always use `--use-uploadlarge` for artifacts >200MB.