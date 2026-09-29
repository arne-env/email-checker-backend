import os
import re
import asyncio
import socket
import urllib.parse
import httpx
from typing import Optional
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Email & URL Security Analyzer")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Keys aus Umgebungsvariablen
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")

TARGET_BRANDS = {
    "strato": ["strato.de", "strato-hosting.eu", "strato.com", "rzone.de"],
    "paypal": ["paypal.com", "paypal.de"],
    "microsoft": ["microsoft.com", "office365.com", "outlook.com", "live.com"],
    "amazon": ["amazon.com", "amazon.de"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "sparkasse": ["sparkasse.de"]
}

SUSPICIOUS_TLDS = ["zip", "mov", "top", "xyz", "work", "click", "loan", "gq", "cf", "tk", "ml"]
CLOUD_STORAGE_DOMAINS = ["s3.amazonaws.com", "amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "firebaseapp.com"]


def unwrap_safelink(url: str) -> str:
    """Entpackt Microsoft SafeLinks und generische Tracker-URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        if "safelinks.protection.outlook.com" in parsed.netloc:
            query_params = urllib.parse.parse_qs(parsed.query)
            if "url" in query_params:
                return query_params["url"][0]
    except Exception:
        pass
    return url


async def resolve_redirects(url: str):
    """Folgt Weiterleitungen und löst die Ziel-URL auf."""
    chain = []
    current_url = url
    async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
        try:
            response = await client.get(current_url)
            for r in response.history:
                chain.append(str(r.url))
            chain.append(str(response.url))
            final_url = str(response.url)
        except Exception:
            final_url = current_url
            chain.append(current_url)
    return final_url, chain


# --- HEADER PARSER & INPUT VALIDATION ---

def parse_email_header(header_text: str) -> dict:
    """Parst E-Mail-Header und prüft auf Vollständigkeit der Kernfelder."""
    if not header_text or not header_text.strip():
        return {"parsed": False, "validation_warnings": []}
    
    validation_warnings = []
    
    from_match = re.search(r"^From:\s*(.*)$", header_text, re.MULTILINE | re.IGNORECASE)
    return_path_match = re.search(r"^Return-Path:\s*<?([^>\s]+)>?", header_text, re.MULTILINE | re.IGNORECASE)
    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", header_text, re.IGNORECASE)
    dmarc_match = re.search(r"dmarc=(pass|fail|none)", header_text, re.IGNORECASE)

    from_val = from_match.group(1).strip() if from_match else ""
    return_path_val = return_path_match.group(1).strip() if return_path_match else ""
    
    # Validation Rules: Fehlende Kerninformationen identifizieren
    if not from_val:
        validation_warnings.append("Header-Warnung: Absender-Feld ('From:') fehlt oder konnte nicht geparst werden.")
    if not return_path_val:
        validation_warnings.append("Header-Warnung: 'Return-Path:' fehlt (wichtig für Rücksende-Authentifizierung).")
    if not spf_match:
        validation_warnings.append("Header-Hinweis: Keine SPF-Testergebnisse ('Received-SPF' / 'spf=...') im Header gefunden.")
    if not dmarc_match:
        validation_warnings.append("Header-Hinweis: Keine DMARC-Auswertung im Header enthalten.")

    # Extrahiere E-Mail Domain aus From
    from_email_match = re.search(r"[\w\.-]+@([\w\.-]+)", from_val)
    from_domain = from_email_match.group(1).lower() if from_email_match else ""

    return {
        "parsed": True,
        "from": from_val,
        "from_domain": from_domain,
        "return_path": return_path_val,
        "spf": spf_match.group(1).lower() if spf_match else "unbekannt",
        "dmarc": dmarc_match.group(1).lower() if dmarc_match else "unbekannt",
        "validation_warnings": validation_warnings
    }


def analyze_email_context(header_text: str, body_text: str, final_domain: str) -> dict:
    """Vergleicht Marken-Erwähnungen im Body/Header mit dem eigentlichen Link-Ziel."""
    score = 0
    warnings = []
    detected_brands = []

    header_info = parse_email_header(header_text)
    
    # 1. Eventuelle Header-Input-Validierungswarnungen übernehmen
    if header_info.get("parsed"):
        for val_warn in header_info.get("validation_warnings", []):
            warnings.append(f"<b>Unvollständige Header-Eingabe:</b> {val_warn}")

    combined_text = f"{header_text} {body_text}".lower()

    # 2. Marken-Abgleich im Text/Header vs. Ziel-Domain
    for brand, valid_domains in TARGET_BRANDS.items():
        if brand in combined_text:
            detected_brands.append(brand)
            if not any(final_domain.endswith(valid) for valid in valid_domains):
                score += 55
                warnings.append(
                    f"<b>Kritischer Kontext-Fehler:</b> Die E-Mail erwähnt '{brand.upper()}', "
                    f"der Ziel-Link führt aber auf eine abweichende Domain (<code>{final_domain}</code>)!"
                )

    # 3. Cloud-Storage Weiterleitungs-Check (z.B. Amazon S3)
    if any(cloud_dom in final_domain.lower() for cloud_dom in CLOUD_STORAGE_DOMAINS):
        score += 35
        warnings.append("<b>Versteckte Weiterleitung:</b> Der Link führt auf einen öffentlichen Cloud-Speicher (Amazon S3/Azure/Google), welcher häufig als Phishing-Versteck genutzt wird.")

    # 4. Absender-Abgleich aus Header
    if header_info.get("parsed"):
        from_dom = header_info.get("from_domain", "")
        if from_dom and detected_brands:
            brand = detected_brands[0]
            valid_doms = TARGET_BRANDS.get(brand, [])
            if not any(from_dom.endswith(v) for v in valid_doms):
                score += 40
                warnings.append(f"<b>Spoofing-Verdacht:</b> E-Mail gibt vor von '{brand.upper()}' zu sein, der Absender im Header ist aber <code>{from_dom}</code>.")

    return {
        "context_score": score,
        "warnings": warnings,
        "detected_brands": detected_brands,
        "header_info": header_info
    }


def analyze_heuristics(hostname: str, sld: str, tld: str) -> dict:
    """Standard-Heuristiken der URL."""
    score = 0
    warnings = []

    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += 40
        warnings.append("Punycode (xn--) erkannt: Möglicher Homoglyphen-Angriff")

    for brand in TARGET_BRANDS.keys():
        if brand in sld.lower() and sld.lower() != brand:
            score += 35
            warnings.append(f"Verdacht auf Typosquatting/Brand Impersonation ('{brand}' in Domain)")

    if tld.lower() in SUSPICIOUS_TLDS:
        score += 20
        warnings.append(f"Statistisch häufig für Phishing genutzte TLD (.{tld})")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        score += 25
        warnings.append("Host ist eine direkte IP-Adresse anstelle eines Domain-Namens")

    return {"heuristic_score": score, "warnings": warnings}


# --- Threat Intel Connectors ---

async def check_virustotal(client: httpx.AsyncClient, domain: str):
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "Kein API Key hinterlegt"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"status": "ok" if stats.get("malicious", 0) == 0 else "malicious", "malicious_count": stats.get("malicious", 0)}
        return {"status": "skipped", "reason": f"HTTP {r.status_code}"}
    except Exception:
        return {"status": "error", "reason": "Timeout / Verbindungsfehler"}

async def check_abuseipdb(client: httpx.AsyncClient, ip: str):
    if not ABUSEIPDB_API_KEY or not ip:
        return {"status": "skipped", "reason": "Kein Key oder keine IP"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        r = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params={"ipAddress": ip, "maxAgeInDays": "90"})
        if r.status_code == 200:
            score = r.json().get("data", {}).get("abuseConfidenceScore", 0)
            return {"status": "ok" if score < 20 else "suspicious", "abuse_score": score}
        return {"status": "skipped", "reason": f"HTTP {r.status_code}"}
    except Exception:
        return {"status": "error", "reason": "Timeout / Verbindungsfehler"}

async def check_greynoise(client: httpx.AsyncClient, ip: str):
    if not GREYNOISE_API_KEY or not ip:
        return {"status": "skipped", "reason": "Kein Key oder keine IP"}
    headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
    try:
        r = await client.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        if r.status_code == 200:
            return {"status": "ok", "noise": r.json().get("noise", False)}
        return {"status": "ok", "reason": "IP unverdächtig"}
    except Exception:
        return {"status": "error", "reason": "Timeout / Verbindungsfehler"}

async def check_urlscan(client: httpx.AsyncClient, domain: str):
    if not URLSCAN_API_KEY:
        return {"status": "skipped", "reason": "Kein API Key hinterlegt"}
    headers = {"API-Key": URLSCAN_API_KEY}
    try:
        r = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", headers=headers)
        if r.status_code == 200:
            results = r.json().get("results", [])
            malicious = sum(1 for res in results if res.get("verdicts", {}).get("overall", {}).get("malicious", False))
            return {"status": "ok" if malicious == 0 else "malicious", "malicious_scans": malicious}
        return {"status": "skipped", "reason": f"HTTP {r.status_code}"}
    except Exception:
        return {"status": "error", "reason": "Timeout / Verbindungsfehler"}

async def check_intelx(client: httpx.AsyncClient, domain: str):
    return {"status": "skipped", "reason": "IntelX API im Free-Tarif nicht verfügbar"}


# --- HAUPT-ENDPOINT ---

@app.get("/api/analyze")
@limiter.limit("10/minute")
async def analyze(
    request: Request, 
    url: str = Query(..., description="Die zu prüfende URL"),
    header: Optional[str] = Query("", description="Optionaler E-Mail Header"),
    body: Optional[str] = Query("", description="Optionaler E-Mail Text/Inhalt")
):
    unwrapped = unwrap_safelink(url)
    is_wrapper = unwrapped != url
    final_url, redirect_chain = await resolve_redirects(unwrapped)
    
    parsed_final = urllib.parse.urlparse(final_url)
    hostname = parsed_final.hostname or ""
    
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else hostname
    main_domain = f"{sld}.{tld}" if sld and tld else hostname

    ip_address = ""
    if hostname:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            pass

    domain_info = {
        "hostname": hostname,
        "sld": sld,
        "tld": tld,
        "mainDomain": main_domain,
        "ip": ip_address
    }

    # 1. Analysen ausführen
    heuristics = analyze_heuristics(hostname, sld, tld)
    context_analysis = analyze_email_context(header, body, main_domain)

    # 2. Threat Intelligence parallel abfragen
    async with httpx.AsyncClient(timeout=5.0) as client:
        vt_res, abuse_res, grey_res, urlscan_res, intelx_res = await asyncio.gather(
            check_virustotal(client, main_domain),
            check_abuseipdb(client, ip_address),
            check_greynoise(client, ip_address),
            check_urlscan(client, main_domain),
            check_intelx(client, main_domain),
            return_exceptions=True
        )

    # 3. Gesamt-Scoring aggregieren
    score = heuristics["heuristic_score"] + context_analysis["context_score"]
    reasons = list(heuristics["warnings"]) + list(context_analysis["warnings"])

    if isinstance(vt_res, dict) and vt_res.get("malicious_count", 0) > 0:
        score += 60
        reasons.append("VirusTotal: Malicious Einstufung")

    if isinstance(abuse_res, dict) and abuse_res.get("abuse_score", 0) > 50:
        score += 30
        reasons.append("AbuseIPDB: Hohe IP-Missbrauchsrate")

    if is_wrapper:
        score += 5
        reasons.append("Microsoft SafeLink Wrapper erkannt")

    return {
        "input_url": url,
        "unwrapped_url": unwrapped,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "is_wrapper": is_wrapper,
        "domain_info": domain_info,
        "heuristics": heuristics,
        "context_analysis": context_analysis,
        "live_threat_intel": {
            "virustotal": vt_res if isinstance(vt_res, dict) else {"status": "error"},
            "abuseipdb": abuse_res if isinstance(abuse_res, dict) else {"status": "error"},
            "greynoise": grey_res if isinstance(grey_res, dict) else {"status": "error"},
            "urlscan": urlscan_res if isinstance(urlscan_res, dict) else {"status": "error"},
            "intelx": intelx_res if isinstance(intelx_res, dict) else {"status": "error"}
        },
        "security_score": {
            "score": min(score, 100),
            "reasons": reasons
        }
    }
