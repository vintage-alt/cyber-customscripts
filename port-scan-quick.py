import sys
import socket

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((host, port))
        
        # Try grabbing banner
        banner = ""
        try:
            # Send a generic probe if needed, or wait for banner
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            pass
            
        print(f"[+] Port {port} is OPEN")
        if banner:
            print(f"    Banner snippet:\n    {banner.splitlines()[0] if banner else 'No banner'}")
        s.close()
    except (socket.timeout, ConnectionRefusedError):
        pass
    except Exception as e:
        print(f"[-] Error on port {port}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python port_banner.py <HOST> [start_port] [end_port]")
        sys.exit(1)
        
    target_host = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    
    print(f"[*] Scanning {target_host} from port {start} to {end}...")
    for p in range(start, end + 1):
        scan_port(target_host, p)