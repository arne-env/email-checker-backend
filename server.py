import os
import asyncio
import socket
import urllib.parse
import httpx
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Rate Limiter konfigurieren (Max. 10 Anfragen pro Minute pro Client-IP)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Email & URL Security Analyzer")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Middleware für Anfragen aus dem Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Keys aus den Scaleway Environment Variables laden
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")


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


# --- Threat Intelligence Connectors ---

async def check_virustotal(client: httpx.AsyncClient, domain: str):
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "Kein API Key hinterlegt"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return {"status": "ok" if malicious == 0 else "malicious", "malicious_count": malicious}
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
    # Sauber überspringen aufgrund der Free-Tier-Einschränkungen
    return {"status": "skipped", "reason": "IntelX API im Free-Tarif nicht verfügbar"}


# --- Haupt-API Endpunkt ---

@app.get("/api/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, url: str = Query(..., description="Die zu prüfende URL")):
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

    async with httpx.AsyncClient(timeout=5.0) as client:
        vt_res, abuse_res, grey_res, urlscan_res, intelx_res = await asyncio.gather(
            check_virustotal(client, main_domain),
            check_abuseipdb(client, ip_address),
            check_greynoise(client, ip_address),
            check_urlscan(client, main_domain),
            check_intelx(client, main_domain),
            return_exceptions=True
        )

    score = 0
    reasons = []

    if isinstance(vt_res, dict) and vt_res.get("malicious_count", 0) > 0:
        score += 60
        reasons.append("VirusTotal: Malicious")

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
