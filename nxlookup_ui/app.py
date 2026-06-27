from flask import Flask, render_template, request, jsonify
from .core import domain_whois, ip_whois, dns_all, ptr_lookup, ssl_check, http_check, is_ip, is_domain, clean_target
from datetime import datetime, timezone
import webview
import threading
import sys

app = Flask(__name__)


def _expiry(exp: str) -> dict:
    if not exp:
        return {"text": "—", "days": None}
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(exp, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            days = (dt - datetime.now(timezone.utc)).days
            return {"text": str(dt)[:19], "days": days}
        except ValueError:
            continue
    return {"text": exp[:19], "days": None}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/lookup", methods=["POST"])
def lookup():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "no target"}), 400

    canonical, display = clean_target(target)

    if is_domain(canonical):
        return jsonify(_lookup_domain(canonical, display))
    elif is_ip(canonical):
        return jsonify(_lookup_ip(canonical))
    else:
        return jsonify({"error": f"'{target}' is not a valid domain or IP"}), 400


def _lookup_domain(domain: str, display: str) -> dict:
    w = domain_whois(domain)
    dns = dns_all(domain)
    ips = dns.get("A", []) + dns.get("AAAA", [])

    exp = _expiry(w.get("expires", ""))

    ip_info = []
    for ip in ips[:8]:
        ptr = ptr_lookup(ip)
        iw = ip_whois(ip)
        ip_info.append({
            "ip": ip,
            "ptr": ptr if ptr != ip else "",
            "org": iw.get("org", ""),
            "netname": iw.get("netname", ""),
            "range": iw.get("inetnum", ""),
            "country": iw.get("country", ""),
            "abuse": iw.get("abuse", ""),
        })

    ssl = ssl_check(domain)
    http = http_check(domain)

    return {
        "type": "domain",
        "target": display,
        "ssl": ssl,
        "http": http,
        "whois": {
            "domain": w.get("domain", ""),
            "registrar": w.get("registrar", ""),
            "whois_server": w.get("whois_server", ""),
            "org": w.get("org", ""),
            "created": w.get("created", "")[:19] if w.get("created") else "",
            "expires": exp["text"],
            "expires_days": exp["days"],
            "updated": w.get("updated", "")[:19] if w.get("updated") else "",
            "country": w.get("country", ""),
            "status": w.get("status", [])[:6],
            "nameservers": w.get("nameservers", [])[:10],
        },
        "dns": {
            "A": dns.get("A", []),
            "AAAA": dns.get("AAAA", []),
            "MX": dns.get("MX", []),
            "NS": dns.get("NS", []),
            "CNAME": dns.get("CNAME", []),
            "SOA": dns.get("SOA", []),
            "TXT": [t[:150] for t in dns.get("TXT", [])[:5]],
        },
        "ip_info": ip_info,
    }


def _lookup_ip(ip: str) -> dict:
    ptr = ptr_lookup(ip)
    iw = ip_whois(ip)
    return {
        "type": "ip",
        "target": ip,
        "ptr": ptr,
        "whois": {
            "range": iw.get("inetnum", ""),
            "netname": iw.get("netname", ""),
            "org": iw.get("org", ""),
            "descr": iw.get("descr", ""),
            "country": iw.get("country", ""),
            "abuse": iw.get("abuse", ""),
        },
    }


def main():
    port = 5050
    url = f"http://127.0.0.1:{port}"

    def start_flask():
        app.run(host="127.0.0.1", port=port, debug=False)

    t = threading.Thread(target=start_flask, daemon=True)
    t.start()

    webview.create_window("nxlookup", url, width=860, height=720, resizable=True)
    webview.start()


if __name__ == "__main__":
    main()