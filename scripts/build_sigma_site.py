import html
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
SIGMA_API = "https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1"
RAW_SIGMA = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/"
MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

TACTIC_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

OS_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "android": "Android",
    "ios": "iOS",
    "azure": "Azure",
    "aws": "AWS",
    "gcp": "GCP",
    "zeek": "Zeek",
    "apache": "Apache",
    "nginx": "Nginx",
    "m365": "Microsoft 365",
    "office365": "Microsoft 365",
    "okta": "Okta",
    "google_workspace": "Google Workspace",
    "kubernetes": "Kubernetes",
    "sysmon": "Sysmon",
    "powershell": "PowerShell",
}

def fetch_json(url):
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    return r.json()

def fetch_text(url):
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    return r.text

def build_technique_lookup(stix):
    lookup = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            ext = ref.get("external_id", "")
            if ref.get("source_name") == "mitre-attack" and ext.startswith("T"):
                lookup[ext.upper()] = obj.get("name", "")
    return lookup

def normalize_tactic(val):
    key = val.lower().replace("-", "_")
    return TACTIC_MAP.get(key, val.replace("_", " ").replace("-", " ").title())

def prettify(value):
    if not value:
        return ""
    value = str(value).strip()
    key = value.lower().replace("-", "_")
    if key in OS_LABELS:
        return OS_LABELS[key]
    if value.isupper() and len(value) <= 6:
        return value
    return value.replace("_", " ").replace("-", " ").title()

def infer_platforms(logsource):
    platforms = []
    if not isinstance(logsource, dict):
        return platforms
    for field in ["product", "service", "category"]:
        val = logsource.get(field)
        if val:
            label = prettify(val)
            if label and label not in platforms:
                platforms.append(label)
    return platforms

def extract_attack(tags, technique_lookup):
    tactics, tids, tnames = [], [], []
    for tag in tags or []:
        if not isinstance(tag, str) or not tag.lower().startswith("attack."):
            continue
        suffix = tag.split(".", 1)[1].strip()
        if re.fullmatch(r"t\d{4}(?:\.\d{3})?", suffix, re.I):
            tid = suffix.upper()
            tids.append(tid)
            if tid in technique_lookup:
                tnames.append(technique_lookup[tid])
        else:
            tactics.append(normalize_tactic(suffix))
    return sorted(set(tactics)), sorted(set(tids)), sorted(set(tnames))

def github_tree_paths():
    data = fetch_json(SIGMA_API)
    return [
        x["path"]
        for x in data.get("tree", [])
        if x.get("type") == "blob" and x["path"].endswith((".yml", ".yaml"))
    ]

def parse_rules():
    stix = fetch_json(MITRE_URL)
    technique_lookup = build_technique_lookup(stix)
    rows = []

    for path in github_tree_paths():
        try:
            raw = fetch_text(RAW_SIGMA + path)
            data = yaml.safe_load(raw)

            if not isinstance(data, dict):
                continue

            title = data.get("title", "")
            if not title:
                continue

            tags = data.get("tags", []) or []
            logsource = data.get("logsource", {}) or {}
            tactics, tids, tnames = extract_attack(tags, technique_lookup)
            platforms = infer_platforms(logsource)

            rows.append({
                "title": str(title),
                "id": str(data.get("id", "")),
                "status": str(data.get("status", "")),
                "level": str(data.get("level", "")),
                "description": str(data.get("description", "")).strip(),
                "tags": tags,
                "tactics": tactics,
                "technique_ids": tids,
                "technique_names": tnames,
                "logsource_product": prettify(logsource.get("product", "")),
                "logsource_service": prettify(logsource.get("service", "")),
                "logsource_category": prettify(logsource.get("category", "")),
                "platforms": platforms,
                "url": f"https://github.com/SigmaHQ/sigma/blob/master/{path}",
                "path": path,
            })
        except Exception:
            continue

    return rows

def shell(title, body, updated):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px;line-height:1.5;color:#1f2937}}
a{{color:#0f766e}}
table{{border-collapse:collapse;width:100%;margin-top:16px}}
th,td{{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}}
.muted{{color:#6b7280}}
input{{width:100%;padding:10px;font-size:16px;margin:12px 0}}
ul{{columns:2;max-width:900px}}
code{{background:#f3f4f6;padding:2px 6px;border-radius:4px}}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="muted">Updated: {html.escape(updated)}</p>
{body}
</body>
</html>"""

def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

def rule_row(r):
    platform_text = ", ".join(r["platforms"])
    logsource_text = " / ".join(
        x for x in [
            r["logsource_product"],
            r["logsource_service"],
            r["logsource_category"]
        ] if x
    )
    return (
        "<tr>"
        f"<td><a href='{html.escape(r['url'])}' target='_blank' rel='noopener noreferrer'>{html.escape(r['title'])}</a></td>"
        f"<td>{html.escape(r['id'])}</td>"
        f"<td>{html.escape(platform_text)}</td>"
        f"<td>{html.escape(logsource_text)}</td>"
        f"<td>{html.escape(', '.join(r['tactics']))}</td>"
        f"<td>{html.escape(', '.join(r['technique_ids']))}</td>"
        f"<td>{html.escape(', '.join(r['technique_names']))}</td>"
        f"<td>{html.escape(r['description'][:220])}</td>"
        "</tr>"
    )

def 
