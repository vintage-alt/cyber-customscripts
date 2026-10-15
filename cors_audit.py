import sys
import requests

def audit_target(url):
    print(f"[*] Auditing target: {url}")
    
    # Test CORS with an arbitrary malicious origin
    test_origin = "https://evil-origin.com"
    headers = {"Origin": test_origin}
    
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        
        print("\n--- CORS Analysis ---")
        if acao == test_origin:
            print(f"[!] VULN/WARNING: Reflected Origin detected! (ACAO: {acao})")
            if acac and acac.lower() == "true":
                print("[!] CRITICAL: Access-Control-Allow-Credentials is set to true with reflected origin!")
        elif acao == "*":
            print("[*] Info: Wildcard ACAO (*) detected.")
        else:
            print("[+] Secure: Origin not blindly reflected.")
            
        print("\n--- Security Headers ---")
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]
        for header in security_headers:
            if header in response.headers:
                print(f"[+] Present: {header} = {response.headers[header]}")
            else:
                print(f"[-] Missing: {header}")
                
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to target: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cors_auditor.py <URL>")
        sys.exit(1)
    audit_target(sys.argv[1])