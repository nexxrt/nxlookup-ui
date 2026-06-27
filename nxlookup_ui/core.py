"""
Core lookup logic extracted from nxlookup.
Pure Python DNS + WHOIS + IP analysis.
"""

import re
import socket
import ipaddress
import subprocess
from typing import Optional

# ── Optional dependencies ──────────────────────────────────────────────

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois as pywhois
    HAS_PYWHOIS = True
except ImportError:
    HAS_PYWHOIS = False

import shutil
HAS_DIG = shutil.which("dig") is not None
HAS_WHOIS = shutil.which("whois") is not None


# ── DNS ────────────────────────────────────────────────────────────────

def dns_resolve(domain: str, rtype: str) -> list[str]:
    """Resolve DNS records. Uses dnspython if available, falls back to dig."""
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            return [str(r).rstrip('.') for r in answers]
        except Exception:
            pass
    if HAS_DIG:
        try:
            out = subprocess.run(["dig", "+short", domain, rtype],
                               capture_output=True, text=True, timeout=15)
            return [l.strip().rstrip('.') for l in out.stdout.splitlines() if l.strip()]
        except Exception:
            pass
    return []


def dns_all(domain: str) -> dict:
    types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    return {t: dns_resolve(domain, t) for t in types}


def ptr_lookup(ip: str) -> str:
    if HAS_DNSPYTHON:
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return str(answers[0]).rstrip('.')
        except Exception:
            pass
    if HAS_DIG:
        try:
            out = subprocess.run(["dig", "+short", "-x", ip],
                               capture_output=True, text=True, timeout=10)
            return out.stdout.strip().rstrip('.')
        except Exception:
            pass
    return ""


# ── WHOIS ──────────────────────────────────────────────────────────────

def _socket_whois(iana_query: str, referral_query: str) -> str:
    try:
        s = socket.create_connection(("whois.iana.org", 43), timeout=10)
        s.sendall((iana_query + "\r\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode("utf-8", errors="replace")

        m = re.search(r'(?i)^refer:\s*(\S+)', text, re.MULTILINE)
        if not m:
            m = re.search(r'(?i)^whois:\s*(\S+)', text, re.MULTILINE)
        if not m:
            return text

        ref_server = m.group(1)
        s2 = socket.create_connection((ref_server, 43), timeout=10)
        s2.sendall((referral_query + "\r\n").encode())
        resp2 = b""
        while True:
            chunk = s2.recv(4096)
            if not chunk:
                break
            resp2 += chunk
        s2.close()
        return resp2.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _domain_whois_socket(domain: str) -> str:
    parts = domain.lower().rstrip('.').split('.')
    if len(parts) >= 2 and parts[-2] in ('co', 'org', 'net', 'com', 'gov', 'ac', 'me', 'ltd', 'plc', 'sch'):
        tld = parts[-2] + '.' + parts[-1]
    else:
        tld = parts[-1]
    return _socket_whois(tld, domain)


def _ip_whois_socket(ip: str) -> str:
    return _socket_whois(ip, ip)


def parse_domain_whois(raw: str) -> dict:
    data = {
        "domain": "", "registrar": "", "whois_server": "", "status": [],
        "nameservers": [], "created": "", "expires": "", "updated": "",
        "registrant": "", "org": "", "country": "",
    }
    patterns = [
        (r'(?i)^\s*Domain Name:\s*(.+)', 'domain'),
        (r'(?i)^\s*domain:\s*(.+)', 'domain'),
        (r'(?i)^\s*Registrar:\s*(.+)', 'registrar'),
        (r'(?i)^\s*registrar:\s*(.+)', 'registrar'),
        (r'(?i)^\s*Registrar WHOIS Server:\s*(.+)', 'whois_server'),
        (r'(?i)^\s*Creation Date:\s*(.+)', 'created'),
        (r'(?i)^\s*created:\s*(.+)', 'created'),
        (r'(?i)^\s*Created:\s*(.+)', 'created'),
        (r'(?i)^\s*Registry Expiry Date:\s*(.+)', 'expires'),
        (r'(?i)^\s*Expiry Date:\s*(.+)', 'expires'),
        (r'(?i)^\s*paid-till:\s*(.+)', 'expires'),
        (r'(?i)^\s*Updated Date:\s*(.+)', 'updated'),
        (r'(?i)^\s*Registrant Organization:\s*(.+)', 'org'),
        (r'(?i)^\s*org:\s*(.+)', 'org'),
        (r'(?i)^\s*Registrant:\s*(.+)', 'registrant'),
        (r'(?i)^\s*Registrant Country:\s*(.+)', 'country'),
    ]
    for pat, key in patterns:
        m = re.search(pat, raw, re.MULTILINE)
        if m and not data[key]:
            data[key] = m.group(1).strip()

    ns_patterns = [
        r'(?i)^\s*Name Server:\s*(.+)',
        r'(?i)^\s*nserver:\s*(.+)',
        r'(?i)^\s*Nserver:\s*(.+)',
    ]
    seen = set()
    for p in ns_patterns:
        for m in re.finditer(p, raw, re.MULTILINE):
            ns = m.group(1).split()[0].rstrip('.')
            if ns and ns not in seen:
                seen.add(ns)
                data["nameservers"].append(ns)

    for m in re.finditer(r'(?i)^\s*(?:Domain |domain |)Status:\s*(.+)', raw, re.MULTILINE):
        data["status"].append(m.group(1).strip())
    for m in re.finditer(r'(?i)^\s*state:\s*(.+)', raw, re.MULTILINE):
        data["status"].append(m.group(1).strip())

    return data


def parse_ip_whois(raw: str) -> dict:
    data = {
        "inetnum": "", "netname": "", "org": "", "country": "",
        "descr": "", "role": "", "abuse": "",
    }
    patterns = [
        (r'(?i)^\s*inetnum:\s*(.+)', 'inetnum'),
        (r'(?i)^\s*NetRange:\s*(.+)', 'inetnum'),
        (r'(?i)^\s*CIDR:\s*(.+)', 'inetnum'),
        (r'(?i)^\s*netname:\s*(.+)', 'netname'),
        (r'(?i)^\s*NetName:\s*(.+)', 'netname'),
        (r'(?i)^\s*(?:org-name|OrgName):\s*(.+)', 'org'),
        (r'(?i)^\s*organisation:\s*(.+)', 'org'),
        (r'(?i)^\s*Organization:\s*(.+)', 'org'),
        (r'(?i)^\s*(?:country|Country):\s*(.+)', 'country'),
        (r'(?i)^\s*descr:\s*(.+)', 'descr'),
        (r'(?i)^\s*role:\s*(.+)', 'role'),
        (r'(?i)^\s*OrgAbuseEmail:\s*(.+)', 'abuse'),
    ]
    for pat, key in patterns:
        m = re.search(pat, raw, re.MULTILINE)
        if m and not data[key]:
            data[key] = m.group(1).strip()
    return data


# ── Unified queries ────────────────────────────────────────────────────

def domain_whois(domain: str) -> dict:
    data = {
        "domain": "", "registrar": "", "whois_server": "", "status": [],
        "nameservers": [], "created": "", "expires": "", "updated": "",
        "registrant": "", "org": "", "country": "",
    }

    if HAS_PYWHOIS:
        try:
            w = pywhois.whois(domain)
            dn = w.get('domain_name')
            if dn: data["domain"] = dn if isinstance(dn, str) else dn[0]
            r = w.get('registrar')
            if r: data["registrar"] = r if isinstance(r, str) else r
            ws = w.get('whois_server')
            if ws: data["whois_server"] = ws if isinstance(ws, str) else ws
            ns = w.get('name_servers')
            if ns:
                for n in ns:
                    if n: data["nameservers"].append(n.split()[0].rstrip('.').lower())
            st = w.get('status')
            if st: data["status"] = st if isinstance(st, list) else [st]
            cd = w.get('creation_date')
            if cd: data["created"] = str(cd if isinstance(cd, str) else cd[0] if isinstance(cd, list) else cd)
            ed = w.get('expiration_date')
            if ed: data["expires"] = str(ed if isinstance(ed, str) else ed[0] if isinstance(ed, list) else ed)
            ud = w.get('updated_date')
            if ud: data["updated"] = str(ud if isinstance(ud, str) else ud[0] if isinstance(ud, list) else ud)
            o = w.get('org')
            if o: data["org"] = o if isinstance(o, str) else o
            c = w.get('country')
            if c: data["country"] = c if isinstance(c, str) else c
            return data
        except Exception:
            pass

    raw = _domain_whois_socket(domain)
    if raw:
        parsed = parse_domain_whois(raw)
        if parsed.get("domain"):
            return parsed

    if HAS_WHOIS:
        try:
            r = subprocess.run(["whois", "-H", domain],
                             capture_output=True, text=True, timeout=20)
            return parse_domain_whois(r.stdout)
        except Exception:
            pass
    return data


def ip_whois(ip: str) -> dict:
    raw = _ip_whois_socket(ip)
    if raw:
        return parse_ip_whois(raw)
    if HAS_WHOIS:
        try:
            r = subprocess.run(["whois", "-H", ip],
                             capture_output=True, text=True, timeout=20)
            return parse_ip_whois(r.stdout)
        except Exception:
            pass
    return {}


# ── Helpers ────────────────────────────────────────────────────────────

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_domain(target: str) -> bool:
    if is_ip(target):
        return False
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z0-9\-]{2,}$', target))


def clean_target(target: str) -> tuple[str, str]:
    """Clean input, handle IDN. Returns (canonical, display) pair."""
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    target = target.split(':')[0]
    target = re.sub(r'^www\.', '', target)

    display = target
    if not target.isascii():
        try:
            target = target.encode('idna').decode('ascii')
        except (UnicodeError, ValueError):
            pass
    return target, display
