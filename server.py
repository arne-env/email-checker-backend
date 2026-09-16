import os
import re
import urllib.parse
import httpx
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Email & URL Security Analyzer")

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
    parsed = urllib.parse.urlparse(url)
    if "safelinks.protection.outlook.com" in parsed.netloc:
        query_params = urllib.parse.parse_qs(parsed.query)
        if "url" in query_params:
            return query_params["url"][0]
    return url


async def resolve_redirects(url: str):
    """Folgt Weiterleitungen und löst IP/Domain-Daten auf."""
    chain = []
    current_url = url
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
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
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = await client.get(url, headers=headers)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return {"status": "ok" if malicious == 0 else "malicious", "malicious_count": malicious, "stats": stats}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def check_abuseipdb(client: httpx.AsyncClient, ip: str):
    if not ABUSEIPDB_API_KEY or not ip:
        return {"status": "skipped", "reason": "Kein API Key oder keine IP"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        r = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {"status": "ok" if score < 20 else "suspicious", "abuse_score": score, "total_reports": data.get("totalReports", 0)}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def check_greynoise(client: httpx.AsyncClient, ip: str):
    if not GREYNOISE_API_KEY or not ip:
        return {"status": "skipped", "reason": "Kein API Key oder keine IP"}
    headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
    try:
        r = await client.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        if r.status_code == 200:
            data = r.json()
            return {"status": "ok", "noise": data.get("noise", False), "riot": data.get("riot", False), "classification": data.get("classification", "unknown")}
        elif r.status_code == 404:
            return {"status": "ok", "message": "IP nicht in GreyNoise DB (unverdächtig)"}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def check_urlscan(client: httpx.AsyncClient, domain: str):
    if not URLSCAN_API_KEY:
        return {"status": "skipped", "reason": "Kein API Key hinterlegt"}
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    try:
        # Erstelle eine Domain-Suchabfrage
        r = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", headers=headers)
        if r.status_code == 200:
            results = r.json().get("results", [])
            total = len(results)
            malicious_scans = sum(1 for res in results if res.get("verdicts", {}).get("overall", {}).get("malicious", False))
            return {"status": "ok" if malicious_scans == 0 else "malicious", "total_scans_found": total, "malicious_scans": malicious_scans}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def check_intelx(client: httpx.AsyncClient, domain: str):
    if not INTELX_API_KEY:
        return {"status": "skipped", "reason": "Kein API Key hinterlegt"}
    headers = {"x-key": INTELX_API_KEY, "Content-Type": "application/json"}
    payload = {"term": domain, "maxresults": 10, "media": 0, "target": 1}
    try:
        r = await client.post("https://2.intelx.io/phonebook/search", headers=headers, json=payload)
        if r.status_code == 200:
            return {"status": "ok", "search_id": r.json().get("id"), "message": "Suchauftrag gestartet"}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# --- Haupt-Endpoint ---

@app.get("/api/analyze")
async def analyze(url: str = Query(..., description="Die zu prüfende URL")):
    unwrapped = unwrap_safelink(url)
    is_wrapper = unwrapped != url
    final_url, redirect_chain = await resolve_redirects(unwrapped)
    
    parsed_final = urllib.parse.urlparse(final_url)
    hostname = parsed_final.hostname or ""
    
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else hostname
    main_domain = f"{sld}.{tld}" if sld and tld else hostname

    # IP-Auflösung (Platzhalter/Fallback)
    ip_address = ""
    try:
        import socket
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

    # Parallele Abfragen aller 5 Dienste
    async with httpx.AsyncClient(timeout=10.0) as client:
        vt_res = await check_virustotal(client, main_domain)
        abuse_res = await check_abuseipdb(client, ip_address)
        grey_res = await check_greynoise(client, ip_address)
        urlscan_res = await check_urlscan(client, main_domain)
        intelx_res = await check_intelx(client, main_domain)

    # Simple Score-Berechnung
    score = 0
    reasons = []

    if vt_res.get("malicious_count", 0) > 0:
        score += 60
        reasons.append(f"VirusTotal: {vt_res['malicious_count']} Malicious Verdict(s)")

    if abuse_res.get("abuse_score", 0) > 20:
        score += 40
        reasons.append(f"AbuseIPDB Score: {abuse_res['abuse_score']}%")

    if urlscan_res.get("malicious_scans", 0) > 0:
        score += 50
        reasons.append(f"Urlscan.io: {urlscan_res['malicious_scans']} bekannte Malicious Scans")

    if is_wrapper:
        score += 5
        reasons.append("Microsoft SafeLink / Redirect Wrapper erkannt")

    return {
        "input_url": url,
        "unwrapped_url": unwrapped,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "is_wrapper": is_wrapper,
        "domain_info": domain_info,
        "live_threat_intel": {
            "virustotal": vt_res,
            "abuseipdb": abuse_res,
            "greynoise": grey_res,
            "urlscan": urlscan_res,
            "intelx": intelx_res
        },
        "security_score": {
            "score": min(score, 100),
            "reasons": reasons
        }
    }
