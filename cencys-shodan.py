from censys.common.exceptions import CensysAPIException
from censys.search import CensysHosts
import shodan

# --- Configuration ---
DOMAIN = "example.com"  # Replace with your target domain
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
CENSYS_API_ID = "YOUR_CENSYS_API_ID"
CENSYS_API_SECRET = "YOUR_CENSYS_API_SECRET"
OUTPUT_FILE = "domain_search_results.txt"


def query_shodan_by_domain(domain, api_key):
  print(f"[*] Querying Shodan for domain: {domain}")
  discovered_hosts = {}
  try:
    api = shodan.Shodan(api_key)
    # Shodan search query syntax for domain
    query = f"hostname:{domain}"
    result = api.search(query)

    for match in result.get("matches", []):
      ip = match.get("ip_str")
      port = match.get("port")
      hostnames = match.get("hostnames", [])

      if ip:
        if ip not in discovered_hosts:
          discovered_hosts[ip] = {"ports": set(), "hostnames": set(hostnames)}
        if port:
          discovered_hosts[ip]["ports"].add(port)

    print(
        f"[+] Shodan found {len(discovered_hosts)} host(s) for domain:"
        f" {domain}"
    )
  except shodan.APIError as e:
    print(f"[-] Shodan API Error: {e}")
  except Exception as e:
    print(f"[-] Unexpected error with Shodan: {e}")

  return discovered_hosts


def query_censys_by_domain(domain, api_id, api_secret):
  print(f"[*] Querying Censys for domain: {domain}")
  discovered_hosts = {}
  try:
    ch = CensysHosts(api_id=api_id, api_secret=api_secret)
    # Censys search query syntax for domain
    query = f"services.dns.names: {domain}"

    # Search Censys hosts
    for host in ch.search(query, max_records=50):
      ip = host.get("ip")
      if ip:
        # Fetch detailed view for services/ports on this host
        host_view = ch.view(ip)
        services = host_view.get("services", [])
        ports = [s.get("port") for s in services if "port" in s]

        if ip not in discovered_hosts:
          discovered_hosts[ip] = {"ports": set(), "services": []}
        for p in ports:
          discovered_hosts[ip]["ports"].add(p)

    print(
        f"[+] Censys found {len(discovered_hosts)} host(s) for domain: {domain}"
    )
  except CensysAPIException as e:
    print(f"[-] Censys API Error: {e}")
  except Exception as e:
    print(f"[-] Unexpected error with Censys: {e}")

  return discovered_hosts


def main():
  # 1. Query Shodan using domain
  shodan_data = query_shodan_by_domain(DOMAIN, SHODAN_API_KEY)

  # 2. Query Censys using domain
  censys_data = query_censys_by_domain(DOMAIN, CENSYS_API_ID, CENSYS_API_SECRET)

  # Merge results from both platforms by IP address
  all_ips = set(list(shodan_data.keys()) + list(censys_data.keys()))

  if not all_ips:
    print(
        "[-] No hosts found matching the domain on Shodan or Censys. Try a"
        " broader or different query."
    )
    return

  print(
      f"\n[+] Consolidated total unique IPs discovered: {len(all_ips)}"
  )

  results = []
  results.append(f"Domain Search & Port Scan Results for: {DOMAIN}\n")
  results.append("=" * 60 + "\n")

  for ip in sorted(all_ips):
    ip_lines = [f"Target IP: {ip}"]

    # Gather Shodan ports for this IP if available
    s_ports = shodan_data.get(ip, {}).get("ports", set())
    s_hostnames = shodan_data.get(ip, {}).get("hostnames", set())
    ip_lines.append(f"  - Associated Hostnames (Shodan): {list(s_hostnames)}")
    ip_lines.append(
        f"  - Shodan Open Ports: {sorted(list(s_ports)) if s_ports else 'None'}"
    )

    # Gather Censys ports for this IP if available
    c_ports = censys_data.get(ip, {}).get("ports", set())
    ip_lines.append(
        f"  - Censys Open Ports: {sorted(list(c_ports)) if c_ports else 'None'}"
    )

    # Combined unique ports
    combined_ports = sorted(list(s_ports.union(c_ports)))
    ip_lines.append(f"  - Combined Open Ports: {combined_ports}")
    ip_lines.append("-" * 60)

    results.append("\n".join(ip_lines) + "\n")

  # Write to file
  with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.writelines(results)

  print(f"\n[+] Done! Results successfully saved to {OUTPUT_FILE}")


if __name__ == "__main__":
  main()
