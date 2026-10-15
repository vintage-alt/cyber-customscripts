import sys
import json
import base64

def base64_url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)

def inspect_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            print("[-] Invalid JWT format. Must have 3 parts separated by dots.")
            return
            
        header_json = json.loads(base64_url_decode(parts[0]).decode('utf-8'))
        payload_json = json.loads(base64_url_decode(parts[1]).decode('utf-8'))
        
        print("\n=== JWT Header ===")
        print(json.dumps(header_json, indent=2))
        
        print("\n=== JWT Payload ===")
        print(json.dumps(payload_json, indent=2))
        
        print("\n=== Security Checks ===")
        alg = header_json.get("alg", "").lower()
        if alg == "none":
            print("[!] CRITICAL: Algorithm set to 'none'. Token lacks signature verification.")
        elif alg.startswith("hs"):
            print("[*] Note: Uses HMAC-based signature. Verify if weak/guessable secret is used.")
        elif alg.startswith("rs"):
            print("[*] Note: Uses RSA-based asymmetric signing.")
            
        if "exp" not in payload_json:
            print("[!] Warning: Token payload lacks an expiration ('exp') claim.")
            
    except Exception as e:
        print(f"[-] Failed to parse JWT: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python jwt_inspector.py <JWT_STRING>")
        sys.exit(1)
    inspect_jwt(sys.argv[1])