import os
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import requests

app = FastAPI(title="Email Protection & Threat Intelligence API")

# CORS erlauben, damit das Frontend bei Infomaniak auf das Backend zugreifen kann
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")

MULTI_PART_TLDS = {'co.uk', 'gov.uk', 'ac.uk', 'com.de', 'co.at', 'com.au', 'co.jp'}

def unwrap_url(raw_url: str) -> str:
    current_url = raw_url.strip()
    if not re.match(r'^https?://', current_url, re.IGNORECASE):
        current_url = 'http://' + current_url

    try:
        parsed = urllib.parse.urlparse(current_url)
        if 'safelinks.protection.outlook.com' in parsed.netloc:
            qs = urllib.parse.parse_qs(parsed.query)
            if 'url' in qs:
                return unwrap_url(qs['url'][0])
        elif 'proofpoint.com' in parsed.netloc:
            qs = urllib.parse.parse_qs(parsed.query)
            if 'u' in qs:
                return unwrap_url(urllib.parse.unquote(qs['u'][0]))
        elif 'google.com' in parsed.netloc and parsed.path == '/url':
            qs = urllib.parse.parse_qs(parsed.query)
            if 'q' in qs:
                return unwrap_url(qs['q'][0])
    except Exception:
        pass
    return current_url

def follow_redirects(url: str, max_redirects: int = 5) -> list:
    chain = [url]
    current = url
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    for _ in range(max_redirects):
        try:
            res = requests.head(current, headers=headers, allow_redirects=False, timeout=3)
            if res.status_code in [301, 302, 303, 307, 308] and 'Location' in res.headers:
                next_url = urllib.parse.urljoin(current, res.headers['Location'])
                next_url = unwrap_url(next_url)
                if next_url == current or next_url in chain:
                    break
                chain.append(next_url)
                current = next_url
            else:
                break
        except Exception:
            break
    return chain

def parse_domain(hostname: str):
    parts = hostname.split('.')
    if len(parts) == 1:
        return {"subdomain": "", "sld": hostname, "tld": "", "mainDomain": hostname}
    
    tld = parts[-1]
    sld = parts[-2]
    subparts = parts[:-2]
    
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) > 2:
        tld = last_two
        sld = parts[-3]
        subparts = parts[:-3]
        
    return {
        "subdomain": ".".join(subparts),
        "sld": sld,
        "tld": tld,
        "mainDomain": f"{sld}.{tld}"
    }

def resolve_dns(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def check_virustotal(domain: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "Kein API Key hinterlegt"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=4)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    return {"status": "error", "message": f"HTTP {res.status_code}"}

def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY or not ip:
        return {"status": "skipped", "reason": "Kein API Key oder keine IP"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        res = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers, timeout=4)
        if res.status_code == 200:
            data = res.json().get("data", {})
            return {
                "status": "ok",
                "abuseScore": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0)
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    return {"status": "error", "message": f"HTTP {res.status_code}"}

def check_greynoise(ip: str) -> dict:
    if not ip:
        return {"status": "skipped", "reason": "Keine IP verfügbar"}
    headers = {"key": GREYNOISE_API_KEY} if GREYNOISE_API_KEY else {}
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        res = requests.get(url, headers=headers, timeout=4)
        if res.status_code == 200:
            data = res.json()
            return {
                "status": "ok",
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown")
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    return {"status": "not_found"}

@app.get("/api/analyze")
def analyze(url: str = Query(...)):
    unwrapped = unwrap_url(url)
    redirect_chain = follow_redirects(unwrapped)
    final_url = redirect_chain[-1]

    parsed_target = urllib.parse.urlparse(final_url)
    hostname = parsed_target.hostname or ""
    domain_components = parse_domain(hostname)
    main_domain = domain_components["mainDomain"]
    
    ip_address = resolve_dns(main_domain)

    with ThreadPoolExecutor() as executor:
        future_vt = executor.submit(check_virustotal, main_domain)
        future_abuse = executor.submit(check_abuseipdb, ip_address)
        future_gn = executor.submit(check_greynoise, ip_address)

        vt_res = future_vt.result()
        abuse_res = future_abuse.result()
        gn_res = future_gn.result()

    live_score = 0
    score_reasons = []

    if vt_res.get("status") == "ok":
        mal = vt_res.get("malicious", 0)
        if mal > 0:
            live_score += min(mal * 25, 70)
            score_reasons.append(f"VirusTotal: {mal} Security-Vendor(s) melden Phishing/Malware.")

    if abuse_res.get("status") == "ok":
        score_val = abuse_res.get("abuseScore", 0)
        if score_val > 20:
            live_score += int(score_val * 0.4)
            score_reasons.append(f"AbuseIPDB Confidence Score liegt bei {score_val}%.")

    if gn_res.get("status") == "ok":
        classification = gn_res.get("classification")
        if classification == "malicious":
            live_score += 40
            score_reasons.append("GreyNoise klassifiziert die Server-IP als bösartig.")

    live_score = min(live_score, 100)

    return {
        "input_url": url,
        "unwrapped_url": unwrapped,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "is_wrapper": url != unwrapped,
        "domain_info": {
            "hostname": hostname,
            "subdomain": domain_components["subdomain"],
            "sld": domain_components["sld"],
            "tld": domain_components["tld"],
            "mainDomain": main_domain,
            "ip": ip_address
        },
        "live_threat_intel": {
            "virustotal": vt_res,
            "abuseipdb": abuse_res,
            "greynoise": gn_res
        },
        "security_score": {
            "score": live_score,
            "reasons": score_reasons
        }
    }
