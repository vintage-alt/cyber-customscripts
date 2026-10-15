import sys
import json
import requests

def audit_graphql(endpoint):
    print(f"[*] Analyzing GraphQL target: {endpoint}")
    headers = {"Content-Type": "application/json", "User-Agent": "GQL-Security-Scanner/1.0"}
    
    # 1. Test Introspection
    introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}
    try:
        r = requests.post(endpoint, json=introspection_query, headers=headers, timeout=10)
        if r.status_code == 200 and "__schema" in r.text:
            print("[!] VULN/INFO: Introspection is ENABLED. Full schema disclosure possible.")
        else:
            print("[+] Secure: Introspection appears disabled or restricted.")
    except Exception as e:
        print(f"[-] Introspection check failed: {e}")

    # 2. Test Field Suggestion / Oracle Behavior
    oracle_query = {"query": "{ nonExistentField9999 }"}
    try:
        r = requests.post(endpoint, json=oracle_query, headers=headers, timeout=10)
        if r.status_code == 400 and "Did you mean" in r.text:
            print("[!] INFO: Field suggestions active (Schema enumeration oracle enabled via error messages).")
    except Exception:
        pass

    # 3. Test Batching / Alias Overloading (DoS vector)
    aliases = " ".join([f"q{i}: __typename" for i in range(100)])
    batch_query = {"query": f"{{{aliases}}}"}
    try:
        r = requests.post(endpoint, json=batch_query, headers=headers, timeout=10)
        if r.status_code == 200 and "q99" in r.text:
            print("[!] VULN/WARNING: Alias overloading / heavy batching permitted (DoS risk).")
        else:
            print("[+] Batching limit enforced or query rejected.")
    except Exception as e:
        print(f"[-] Batching check error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gql_scanner.py <GRAPHQL_ENDPOINT_URL>")
        sys.exit(1)
    audit_graphql(sys.argv[1])