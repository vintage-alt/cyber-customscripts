import asyncio
import socket
import requests
import re
import time
import os
import html
import json
import subprocess
from datetime import datetime


# --- Configuration ---
DOMAINS_INPUT = "daskalos.com, idtech.com"
OUTPUT_HTML = "port_monitor_report.html"
SCREENSHOT_DIR = "screenshots"

SUBFINDER_PATH = r"C:\vintage\tools\subfinder_2.17.0_windows_386\subfinder.exe"
SUBFINDER_TIMEOUT = 300  # seconds — subfinder can take a while with many sources
SUBFINDER_SILENT = True   # only output subdomains, no banner

HTTP_TIMEOUT_MS = 8000
MAX_CONCURRENT_PROBES = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) recon-monitor/1.0"

SKIP_PROBE_PORTS = {22, 25, 110, 143, 465, 587, 993, 995, 3306, 5432, 6379, 27017, 11211}

os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def parse_domains(raw):
    domains = [d.strip().lower() for d in raw.split(",") if d.strip()]
    seen, unique = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


# ---------- Step 1: subfinder ----------
def get_subdomains_subfinder(domains):
    """
    Run subfinder against a list of domains. Returns a set of subdomains.
    Uses -dL with a temp file for bulk domain input.
    """
    if not os.path.isfile(SUBFINDER_PATH):
        print(f"[-] subfinder not found at: {SUBFINDER_PATH}")
        print(f"[-] Check the path and try again.")
        return set()

    # Write domains to a temp file for -dL
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for d in domains:
            f.write(d + "\n")
        temp_file = f.name

    cmd = [
        SUBFINDER_PATH,
        "-dL", temp_file,
        "-silent",  # only subdomains, no banner
        "-o", os.path.join(os.getcwd(), "_subfinder_raw.txt"),
        "-timeout", "30",
        "-max-time", "10",
    ]

    print(f"[*] Running subfinder on {len(domains)} domain(s)...")
    print(f"    Command: {' '.join(cmd)}")

    subdomains = set()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBFINDER_TIMEOUT,
            encoding="utf-8",
            errors="replace",
        )

        # subfinder writes to -o file; also stdout may have results
        raw_output = result.stdout or ""

        # Read the output file if it exists
        output_file = os.path.join(os.getcwd(), "_subfinder_raw.txt")
        if os.path.isfile(output_file):
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                raw_output = f.read()
            os.remove(output_file)  # clean up

        for line in raw_output.splitlines():
            line = line.strip().lower()
            if not line:
                continue
            # subfinder may print status lines with -v; filter those
            if line.startswith("[") or " " in line:
                continue
            # Only keep valid-looking hostnames
            if re.match(r"^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$", line):
                subdomains.add(line)

        if result.stderr:
            # subfinder prints some info to stderr even in silent mode
            stderr_lines = result.stderr.strip().splitlines()
            for sl in stderr_lines[:5]:  # show first few
                print(f"    [stderr] {sl}")
                
        time.sleep(2)  # <-- ADDED: let subfinder fully release file handles
        print(f"[+] subfinder: {len(subdomains)} unique subdomains found.")

    except subprocess.TimeoutExpired:
        print(f"[-] subfinder timed out after {SUBFINDER_TIMEOUT}s.")
    except Exception as e:
        print(f"[-] subfinder error: {e}")
    finally:
        try:
            os.unlink(temp_file)
        except Exception:
            pass

    return subdomains


# ---------- Step 2: DNS ----------
def resolve_hostname(hostname):
    ips = set()
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for item in info:
            ip = item[4][0]
            if ip:
                ips.add(ip)
    except socket.gaierror:
        pass
    except Exception as e:
        print(f"[-] Resolution error for {hostname}: {e}")
    return ips


# ---------- Step 3: InternetDB ----------
def query_internetdb(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"[-] InternetDB error for {ip}: {e}")
        return None


# ---------- Step 4: Playwright probing with screenshots ----------
async def probe_one(browser, ip, port, semaphore):
    async with semaphore:
        summary = {
            "ip": ip,
            "port": port,
            "http": None,
            "https": None,
            "screenshot": None,
            "screenshot_scheme": None,
        }

        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent=USER_AGENT,
        )
        page = await context.new_page()
        page.set_default_timeout(HTTP_TIMEOUT_MS)

        for scheme in ("http", "https"):
            url = f"{scheme}://{ip}:{port}"
            entry = {
                "status": None,
                "title": None,
                "final_url": None,
                "error": None,
            }
            try:
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=HTTP_TIMEOUT_MS
                )
                if response:
                    entry["status"] = response.status
                title = await page.title()
                entry["title"] = (title or "No Title").strip()[:200] or "No Title"
                entry["final_url"] = page.url

                if summary["screenshot"] is None:
                    safe_ip = ip.replace(".", "_")
                    fname = f"{safe_ip}_{port}_{scheme}.png"
                    fpath = os.path.join(SCREENSHOT_DIR, fname)
                    try:
                        await page.screenshot(path=fpath, full_page=True)
                        summary["screenshot"] = fpath
                        summary["screenshot_scheme"] = scheme
                    except Exception as e:
                        print(f"    [-] Screenshot failed for {url}: {e}")

            except Exception as e:
                entry["error"] = f"{type(e).__name__}: {str(e)[:100]}"

            summary[scheme] = entry

        await context.close()
        return summary


async def probe_all_ports(ip_to_data):
    from playwright.async_api import async_playwright

    tasks_meta = []
    for ip, data in ip_to_data.items():
        for port in data.get("ports", []):
            if port in SKIP_PROBE_PORTS:
                continue
            tasks_meta.append((ip, port))

    if not tasks_meta:
        print("[*] No web-probeable ports found.")
        return []

    print(f"\n[*] Probing {len(tasks_meta)} ip:port pairs with Playwright...")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROBES)
    results = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        async def run(ip, port):
            try:
                r = await probe_one(browser, ip, port, semaphore)
                results.append(r)
                http_status = r["http"]["status"] if r["http"] else "err"
                https_status = r["https"]["status"] if r["https"] else "err"
                print(f"    [+] {ip}:{port} http={http_status} https={https_status} "
                      f"shot={r['screenshot'] or 'none'}")
            except Exception as e:
                print(f"    [-] Probe error {ip}:{port}: {e}")

        await asyncio.gather(*(run(ip, port) for ip, port in tasks_meta))
        await browser.close()

    return results


# ---------- Step 5: HTML report ----------
def esc(s):
    return html.escape(str(s)) if s is not None else ""


def build_html_report(domains, results, probe_results):
    ip_to_data = results.get("ip_to_data", {})
    hostname_to_ips = results.get("hostname_to_ips", {})
    all_subdomains = results.get("subdomains", set())

    ips_sorted = sorted(ip_to_data.keys())
    probe_sorted = sorted(probe_results, key=lambda x: (x["ip"], x["port"]))
    generated = datetime.now().isoformat()

    css = """
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, sans-serif;
             background: #0f1115; color: #e6e6e6; margin: 0; padding: 24px; }
      h1, h2, h3 { color: #fff; }
      a { color: #6cb6ff; text-decoration: none; }
      a:hover { text-decoration: underline; }
      .meta { color: #888; font-size: 13px; margin-bottom: 24px; }
      .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr);
                      gap: 12px; margin-bottom: 24px; }
      .card { background: #1a1d23; border: 1px solid #2a2f38;
              border-radius: 8px; padding: 14px; }
      .card .num { font-size: 26px; font-weight: 700; color: #fff; }
      .card .lbl { font-size: 12px; color: #999; text-transform: uppercase;
                   letter-spacing: 0.5px; }
      table { width: 100%; border-collapse: collapse; margin-bottom: 32px;
              background: #1a1d23; border-radius: 8px; overflow: hidden; }
      th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #2a2f38;
               font-size: 13px; vertical-align: top; }
      th { background: #232831; color: #bbb; font-weight: 600; font-size: 12px;
           text-transform: uppercase; letter-spacing: 0.5px; }
      tr:hover td { background: #1f232b; }
      .status-2xx { color: #4ade80; font-weight: 600; }
      .status-3xx { color: #fbbf24; font-weight: 600; }
      .status-4xx { color: #f97316; font-weight: 600; }
      .status-5xx { color: #ef4444; font-weight: 600; }
      .status-err { color: #888; font-style: italic; }
      .scheme-http { color: #f59e0b; font-weight: 600; }
      .scheme-https { color: #22d3ee; font-weight: 600; }
      .port { font-family: Consolas, Monaco, monospace; }
      .ip { font-family: Consolas, Monaco, monospace; font-weight: 600; }
      .title { color: #cbd5e1; }
      img.shot { max-width: 260px; max-height: 160px; border-radius: 4px;
                 border: 1px solid #2a2f38; cursor: pointer; }
      .tags span { display: inline-block; background: #2a2f38; color: #cbd5e1;
                   padding: 2px 7px; border-radius: 4px; font-size: 11px;
                   margin-right: 4px; }
      .vuln { color: #ef4444; font-family: Consolas, monospace; font-size: 12px; }
      .section { margin-bottom: 40px; }
    </style>
    """

    def status_class(code_or_err):
        if isinstance(code_or_err, int):
            if 200 <= code_or_err < 300: return "status-2xx"
            if 300 <= code_or_err < 400: return "status-3xx"
            if 400 <= code_or_err < 500: return "status-4xx"
            if 500 <= code_or_err < 600: return "status-5xx"
        return "status-err"

    def cell_status(entry):
        if not entry:
            return '<span class="status-err">—</span>'
        if entry.get("error"):
            return f'<span class="status-err">{esc(entry["error"])}</span>'
        code = entry.get("status")
        if code is None:
            return '<span class="status-err">—</span>'
        return f'<span class="{status_class(code)}">{code}</span>'

    def cell_title(entry):
        if not entry or not entry.get("title"):
            return ""
        return f'<span class="title">{esc(entry["title"])}</span>'

    summary_html = f"""
    <div class="summary-grid">
      <div class="card"><div class="num">{len(all_subdomains)}</div>
        <div class="lbl">Subdomains</div></div>
      <div class="card"><div class="num">{len(hostname_to_ips)}</div>
        <div class="lbl">Resolved hosts</div></div>
      <div class="card"><div class="num">{len(ip_to_data)}</div>
        <div class="lbl">Unique IPs</div></div>
      <div class="card"><div class="num">{len(probe_results)}</div>
        <div class="lbl">Ports probed</div></div>
    </div>
    """

    ip_rows = []
    for ip in ips_sorted:
        data = ip_to_data[ip]
        ports = data.get("ports", [])
        ports_html = " ".join(f'<span class="port">{p}</span>' for p in ports) or "—"
        hostnames = data.get("hostnames", [])
        hostnames_html = "<br>".join(esc(h) for h in hostnames) or "—"
        vulns = data.get("vulns", [])
        vulns_html = "<br>".join(f'<span class="vuln">{esc(v)}</span>' for v in vulns) or "—"
        tags = data.get("tags", [])
        tags_html = " ".join(f'<span>{esc(t)}</span>' for t in tags) or "—"

        ip_rows.append(f"""
        <tr>
          <td class="ip">{esc(ip)}</td>
          <td>{ports_html}</td>
          <td>{hostnames_html}</td>
          <td class="tags">{tags_html}</td>
          <td>{vulns_html}</td>
        </tr>""")

    ip_table = f"""
    <table>
      <thead><tr>
        <th>IP</th><th>Open ports</th><th>Shodan hostnames</th>
        <th>Tags</th><th>Vulns</th>
      </tr></thead>
      <tbody>{''.join(ip_rows)}</tbody>
    </table>
    """

    probe_rows = []
    for r in probe_sorted:
        ip = r["ip"]; port = r["port"]
        http = r.get("http") or {}
        https = r.get("https") or {}
        shot = r.get("screenshot")

        if shot and os.path.exists(shot):
            shot_rel = os.path.relpath(shot).replace("\\", "/")
            shot_html = (f'<a href="{esc(shot_rel)}" target="_blank">'
                         f'<img class="shot" src="{esc(shot_rel)}"></a>')
        else:
            shot_html = '<span class="status-err">no screenshot</span>'

        http_html = (
            f'<span class="scheme-http">HTTP</span> {cell_status(http)}<br>'
            f'<span class="title">{cell_title(http)}</span>'
        )
        https_html = (
            f'<span class="scheme-https">HTTPS</span> {cell_status(https)}<br>'
            f'<span class="title">{cell_title(https)}</span>'
        )

        probe_rows.append(f"""
        <tr>
          <td class="ip">{esc(ip)}<br><span class="port">:{port}</span></td>
          <td>{http_html}</td>
          <td>{https_html}</td>
          <td>{shot_html}</td>
        </tr>""")

    probe_table = f"""
    <table>
      <thead><tr>
        <th>Target</th><th>HTTP</th><th>HTTPS</th><th>Screenshot</th>
      </tr></thead>
      <tbody>{''.join(probe_rows)}</tbody>
    </table>
    """

    mapping_rows = []
    for h in sorted(hostname_to_ips.keys()):
        ips = ", ".join(esc(i) for i in sorted(hostname_to_ips[h]))
        mapping_rows.append(f'<tr><td>{esc(h)}</td><td class="ip">{ips}</td></tr>')

    mapping_table = f"""
    <table>
      <thead><tr><th>Hostname</th><th>Resolved IPs</th></tr></thead>
      <tbody>{''.join(mapping_rows)}</tbody>
    </table>
    """

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Port Monitor Report — {esc(', '.join(domains))}</title>
  {css}
</head>
<body>
  <h1>Passive Port Monitor Report</h1>
  <div class="meta">
    Generated {esc(generated)} &middot;
    Domains: {esc(', '.join(domains))}
  </div>

  {summary_html}

  <div class="section">
    <h2>Web Probe Results</h2>
    {probe_table}
  </div>

  <div class="section">
    <h2>Per-IP Detail (Shodan InternetDB)</h2>
    {ip_table}
  </div>

  <div class="section">
    <h2>Hostname → IP Mapping</h2>
    {mapping_table}
  </div>
</body>
</html>"""

    return doc


def write_html_report(domains, results, probe_results):
    doc = build_html_report(domains, results, probe_results)
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"\n[+] HTML report written to: {OUTPUT_HTML}")
    print(f"[+] Screenshots stored in: ./{SCREENSHOT_DIR}/")


# ---------- Orchestration ----------
async def run_pipeline_async(domains):
    all_subdomains = set()
    all_ips = set()

    # Step 1: subfinder
    time.sleep(1)  # <-- ADDED: brief pause before launching external tool
    all_subdomains = get_subdomains_subfinder(domains)

    if not all_subdomains:
        print("[-] No subdomains found.")
        return {}, []

    print(f"\n[*] Total unique subdomains to resolve: {len(all_subdomains)}")

    # Step 2: DNS
    hostname_to_ips = {}
    for hostname in sorted(all_subdomains):
        ips = resolve_hostname(hostname)
        if ips:
            hostname_to_ips[hostname] = ips
            all_ips.update(ips)
        time.sleep(0.1)  # <-- ADDED: avoid hammering the resolver


    if not all_ips:
        print("[-] No IPs resolved.")
        return {}, []

    print(f"[*] Total unique IPs to query: {len(all_ips)}")

    # Step 3: InternetDB
    ip_to_data = {}
    for ip in sorted(all_ips):
        data = query_internetdb(ip)
        if data:
            ip_to_data[ip] = data
            print(f"[+] {ip}: ports={data.get('ports', [])}, "
                  f"tags={data.get('tags', [])}")
        else:
            print(f"[*] {ip}: no InternetDB data")
        time.sleep(1.5)  # <-- ADDED: InternetDB is free/rate-limited; be polite


    results = {
        "subdomains": all_subdomains,
        "hostname_to_ips": hostname_to_ips,
        "ip_to_data": ip_to_data,
    }

    # Step 4: Playwright probing
    probe_results = await probe_all_ports(ip_to_data)

    return results, probe_results


def main():
    domains = parse_domains(DOMAINS_INPUT)
    if not domains:
        print("[-] No domains provided.")
        return

    print(f"[*] Domains: {domains}\n")

    results, probe_results = asyncio.run(run_pipeline_async(domains))

    if results:
        write_html_report(domains, results, probe_results)

    print("[+] Done.")


if __name__ == "__main__":
    main()
