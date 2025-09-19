#!/usr/bin/env python3
# Bulk Veracode uploader with autoscan or deterministic modes
# Requirements: pip install requests veracode-api-signing
# Auth: VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET or ~/.veracode/credentials

import argparse
import os
import sys
import time
from pathlib import Path
import xml.etree.ElementTree as ET
import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# ---------- helpers ----------

def build_base_urls():
    base = os.getenv("VERACODE_ANALYZER_BASE", "https://analysiscenter.veracode.com")
    return {
        "applist": f"{base}/api/5.0/getapplist.do",
        "createapp": f"{base}/api/5.0/createapp.do",
        "uploadfile": f"{base}/api/5.0/uploadfile.do",
        "uploadlargefile": f"{base}/api/5.0/uploadlargefile.do",
        "beginprescan": f"{base}/api/5.0/beginprescan.do",
        "getbuildinfo": f"{base}/api/5.0/getbuildinfo.do",
        "getprescanresults": f"{base}/api/5.0/getprescanresults.do",
        "beginscan": f"{base}/api/5.0/beginscan.do",
    }

def parse_xml(text):
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        raise RuntimeError(f"XML parse error: {e}\n{text[:600]}...")

def canonical_app_name(prefix, artifact_path):
    stem = Path(artifact_path).stem
    return f"{prefix}{stem}".strip()

def get_app_id(session, urls, target_name):
    r = session.get(urls["applist"])
    r.raise_for_status()
    root = parse_xml(r.text)
    for app in root.iter():
        if app.tag.endswith("app") and app.attrib.get("app_name") == target_name:
            return app.attrib.get("app_id")
    return None

def create_app(session, urls, app_name, criticality, description=None):
    data = {"app_name": app_name, "business_criticality": criticality}
    if description:
        data["description"] = description
    r = session.post(urls["createapp"], data=data)
    r.raise_for_status()
    root = parse_xml(r.text)
    for el in root.iter():
        if el.tag.endswith("application"):
            return el.attrib.get("app_id")
    raise RuntimeError(f"createapp: app_id not found for '{app_name}'")

def upload_artifact(session, urls, app_id, artifact_path, sandbox_id=None, use_large=False):
    url = urls["uploadlargefile"] if use_large else urls["uploadfile"]
    data = {"app_id": str(app_id)}
    if sandbox_id:
        data["sandbox_id"] = str(sandbox_id)
    with open(artifact_path, "rb") as f:
        files = {"file": (os.path.basename(artifact_path), f, "application/octet-stream")}
        r = session.post(url, data=data, files=files)
    r.raise_for_status()
    return True

def begin_prescan(session, urls, app_id, sandbox_id=None, auto_scan=False,
                  include_new_modules=True, scan_all_nonfatal=True):
    data = {"app_id": str(app_id)}
    if sandbox_id:
        data["sandbox_id"] = str(sandbox_id)
    if auto_scan:
        data["auto_scan"] = "true"
    if include_new_modules:
        data["include_new_modules"] = "true"
    if scan_all_nonfatal:
        data["scan_all_nonfatal_top_level_modules"] = "true"
    r = session.post(urls["beginprescan"], data=data)
    r.raise_for_status()
    return True

def get_prescan_status(session, urls, app_id, sandbox_id=None):
    params = {"app_id": str(app_id)}
    if sandbox_id:
        params["sandbox_id"] = str(sandbox_id)
    r = session.get(urls["getbuildinfo"], params=params)
    r.raise_for_status()
    root = parse_xml(r.text)
    for el in root.iter():
        if el.tag.endswith("analysis_unit"):
            return el.attrib.get("status") or "Unknown"
    return "Unknown"

def prescan_ready_and_modules(session, urls, app_id, sandbox_id=None, top_level_only=True):
    params = {"app_id": str(app_id)}
    if sandbox_id:
        params["sandbox_id"] = str(sandbox_id)
    r = session.get(urls["getprescanresults"], params=params)
    r.raise_for_status()
    root = parse_xml(r.text)
    modules = []
    for el in root.iter():
        if el.tag.endswith("module"):
            attrs = el.attrib
            if (not top_level_only) or (attrs.get("top_level", "").lower() == "true"):
                modules.append(attrs.get("id") or attrs.get("name"))
    return (len(modules) > 0, modules if modules else None)

def begin_full_scan(session, urls, app_id, sandbox_id=None,
                    selection_mode="all-top-level", modules=None):
    data = {"app_id": str(app_id)}
    if sandbox_id:
        data["sandbox_id"] = str(sandbox_id)

    if selection_mode == "all-top-level":
        data["scan_all_top_level_modules"] = "true"
    elif selection_mode == "from-prescan":
        if not modules:
            raise RuntimeError("from-prescan selected but modules list is empty")
        data["modules"] = ",".join(modules)
        data["scan_selected_modules"] = "true"
    elif selection_mode == "previous":
        data["scan_previously_selected_modules"] = "true"
    else:
        raise RuntimeError(f"Unknown selection_mode: {selection_mode}")

    r = session.post(urls["beginscan"], data=data)
    r.raise_for_status()
    return True

# ---------- main ----------

def main():
    parser = argparse.ArgumentParser(description="Bulk Veracode upload + scan")
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--glob", default="*.zip")
    parser.add_argument("--prefix", default=None)
    parser.add_argument("--criticality", default="Medium",
                        choices=["Very High", "High", "Medium", "Low", "Very Low"])
    parser.add_argument("--region-base", default=None)
    parser.add_argument("--use-uploadlarge", action="store_true")
    parser.add_argument("--sandbox-id", default=None)
    parser.add_argument("--select", default="all-top-level",
                        choices=["all-top-level", "from-prescan", "previous"])
    parser.add_argument("--poll-interval", type=int, default=45)
    parser.add_argument("--global-timeout", type=int, default=7200)
    parser.add_argument("--mode", default="autoscan",
                        choices=["deterministic", "autoscan"],
                        help="deterministic (prescan+poll+beginscan) or autoscan (fire-and-forget)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.region_base:
        os.environ["VERACODE_ANALYZER_BASE"] = args.region_base

    urls = build_base_urls()
    session = requests.Session()
    session.auth = RequestsAuthPluginVeracodeHMAC()

    artifacts = sorted(Path(args.artifacts_dir).glob(args.glob))
    if not artifacts:
        print("No artifacts found.", file=sys.stderr)
        sys.exit(2)

    if args.mode == "autoscan":
        # --- auto scan ---
        for artifact in artifacts:
            app_name = canonical_app_name(args.prefix, artifact)
            print(f"\n=== {artifact.name} -> '{app_name}' ===")
            app_id = get_app_id(session, urls, app_name)
            if not app_id:
                app_id = create_app(session, urls, app_name, args.criticality)
            upload_artifact(session, urls, app_id, str(artifact),
                            sandbox_id=args.sandbox_id, use_large=args.use_uploadlarge)
            begin_prescan(session, urls, app_id, sandbox_id=args.sandbox_id, auto_scan=True)
            print(f"[{app_name}] Prescan submitted with auto_scan=true (upload-and-forget).")
        print("\nAll artifacts submitted in autoscan mode. The platform will launch scans automatically where possible.")
        return

    # --- Deterministic mode (poll → beginscan) ---
    pending = {}
    for artifact in artifacts:
        app_name = canonical_app_name(args.prefix, artifact)
        print(f"\n=== {artifact.name} -> '{app_name}' ===")
        app_id = get_app_id(session, urls, app_name)
        if not app_id:
            app_id = create_app(session, urls, app_name, args.criticality)
        upload_artifact(session, urls, app_id, str(artifact),
                        sandbox_id=args.sandbox_id, use_large=args.use_uploadlarge)
        begin_prescan(session, urls, app_id, sandbox_id=args.sandbox_id, auto_scan=False)
        pending[str(app_id)] = {
            "name": app_name,
            "sandbox_id": args.sandbox_id,
            "selection": args.select,
            "begun": False,
            "failed": False,
        }

    deadline = time.time() + args.global_timeout
    while pending and time.time() < deadline:
        progressed = 0
        for app_id, meta in list(pending.items()):
            if meta["begun"] or meta["failed"]:
                continue
            ready, modules = prescan_ready_and_modules(session, urls, app_id,
                                                       sandbox_id=meta["sandbox_id"],
                                                       top_level_only=True)
            if ready:
                try:
                    sel = meta["selection"]
                    mods = modules if sel == "from-prescan" else None
                    begin_full_scan(session, urls, app_id, sandbox_id=meta["sandbox_id"],
                                    selection_mode=sel, modules=mods)
                    meta["begun"] = True
                    progressed += 1
                    print(f"[{meta['name']}] Full scan submitted (selection='{sel}').")
                except requests.HTTPError as e:
                    if "prescan" in str(e).lower():
                        if args.verbose:
                            print(f"[{meta['name']}] beginscan not ready; retrying.")
                    else:
                        meta["failed"] = True
                        print(f"[{meta['name']}] beginscan error: {e}", file=sys.stderr)
            else:
                if args.verbose:
                    status = get_prescan_status(session, urls, app_id, sandbox_id=meta["sandbox_id"])
                    print(f"[{meta['name']}] prescan not ready (status: {status}).")
        for app_id in list(pending.keys()):
            if pending[app_id]["begun"] or pending[app_id]["failed"]:
                pending.pop(app_id)
        if not pending:
            break
        if progressed == 0 and args.verbose:
            print(f"No changes this cycle; sleeping {args.poll_interval}s...")
        time.sleep(args.poll_interval)

    if pending:
        print(f"\nStopped with {len(pending)} builds still pending (timeout).", file=sys.stderr)
    else:
        print("\nAll eligible scans have been started.")

if __name__ == "__main__":
    main()