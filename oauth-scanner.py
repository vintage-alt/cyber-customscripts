import sys
import urllib.parse
import requests

def audit_oauth(auth_endpoint, client_id):
    print(f"[*] Auditing OAuth Authorization Endpoint: {auth_endpoint}")
    
    evil_redirect = "https://evil-attacker.com/callback"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": evil_redirect,
        "scope": "openid profile email"
        # Intentionally omitting 'state' or injecting open redirect
    }
    
    target_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
    
    try:
        response = requests.get(target_url, allow_redirects=False, timeout=5)
        print(f"[*] Testing arbitrary redirect_uri value...")
        
        if response.status_code in [301, 302, 303, 307]:
            location = response.headers.get("Location", "")
            if "evil-attacker.com" in location:
                print(f"[!] VULN/CRITICAL: Open Redirect via OAuth `redirect_uri` confirmed! Server redirects to: {location}")
            else:
                print(f"[+] Secure: Authorization server rejected or sanitized external redirect_uri (Redirected to: {location})")
        else:
            print(f"[-] Unexpected response status code: {response.status_code}")
            
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python oauth_auditor.py <AUTH_ENDPOINT_URL> <CLIENT_ID>")
        sys.exit(1)
    audit_oauth(sys.argv[1], sys.argv[2])